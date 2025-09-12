package proxify

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"

	rbtransport "github.com/projectdiscovery/roundrobin/transport"
	"golang.org/x/net/proxy"
)

type httpProxyDialer struct {
	proxyURL *url.URL
	forward  proxy.Dialer
}

// Dial connects to the address using the HTTP proxy.
func (d *httpProxyDialer) Dial(_, addr string) (net.Conn, error) {
	conn, err := d.forward.Dial("tcp", d.proxyURL.Host)
	if err != nil {
		return nil, err
	}

	connectReq := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}
	if d.proxyURL.User != nil {
		encodedUserinfo := base64.StdEncoding.EncodeToString([]byte(d.proxyURL.User.String()))
		connectReq.Header.Set("Proxy-Authorization", "Basic "+encodedUserinfo)
	}

	if err := connectReq.Write(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, connectReq)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("unexpected response from proxy: %s", resp.Status)
	}

	return conn, nil
}

type httpProxyRoundRobinDialer struct {
	proxyDialers map[string]httpProxyDialer
	transport    *rbtransport.RoundTransport
}

// Dial connects to the address on the named network via one of the HTTP proxies using round-robin scheduling.
func (d *httpProxyRoundRobinDialer) Dial(network, addr string) (net.Conn, error) {
	nextProxyURL := d.transport.Next()
	dialer, ok := d.proxyDialers[nextProxyURL]
	if !ok {
		return nil, fmt.Errorf("no matching proxy dialer found")
	}
	return dialer.Dial(network, addr)
}

func newHTTPProxyRoundRobinDialer(upstreamProxies []string) (proxy.Dialer, error) {
	if len(upstreamProxies) == 0 {
		return nil, fmt.Errorf("proxy URLs cannot be empty")
	}

	proxyURLs := make([]*url.URL, 0, len(upstreamProxies))
	dialers := make(map[string]httpProxyDialer)
	for _, proxyAddr := range upstreamProxies {
		proxyURL, err := url.Parse(proxyAddr)
		if err != nil {
			return nil, err
		}
		proxyURLs = append(proxyURLs, proxyURL)
		dialer := httpProxyDialer{proxyURL: proxyURL, forward: proxy.Direct}
		dialers[proxyURL.String()] = dialer
	}

	robin, err := rbtransport.NewWithOptions(1, toStringSlice(proxyURLs)...)
	if err != nil {
		return nil, err
	}

	return &httpProxyRoundRobinDialer{proxyDialers: dialers, transport: robin}, nil
}

type socks5ProxyRoundRobinDialer struct {
	proxyDialers map[string]proxy.Dialer
	robin        *rbtransport.RoundTransport
}

// Dial connects to the address on the named network via one of the SOCKS5 proxies using round-robin scheduling.
func (d *socks5ProxyRoundRobinDialer) Dial(network, addr string) (net.Conn, error) {
	nextProxyURL := d.robin.Next()
	dialer, ok := d.proxyDialers[nextProxyURL]
	if !ok {
		return nil, fmt.Errorf("no matching proxy dialer found")
	}
	return dialer.Dial(network, addr)
}

func newSOCKS5ProxyRoundRobinDialer(upstreamProxies []string) (proxy.Dialer, error) {
	if len(upstreamProxies) == 0 {
		return nil, fmt.Errorf("proxy URLs cannot be empty")
	}

	proxyURLs := make([]*url.URL, 0, len(upstreamProxies))
	dialers := make(map[string]proxy.Dialer)
	for _, proxyAddr := range upstreamProxies {
		proxyURL, err := url.Parse(proxyAddr)
		if err != nil {
			return nil, err
		}
		proxyURLs = append(proxyURLs, proxyURL)
		var auth *proxy.Auth
		if proxyURL.User != nil {
			password, _ := proxyURL.User.Password()
			auth = &proxy.Auth{
				User:     proxyURL.User.Username(),
				Password: password,
			}
		}
		dialer, err := proxy.SOCKS5("tcp", proxyURL.Host, auth, proxy.Direct)
		if err != nil {
			return nil, err
		}
		dialers[proxyAddr] = dialer
	}

	robin, err := rbtransport.NewWithOptions(1, toStringSlice(proxyURLs)...)
	if err != nil {
		return nil, err
	}

	return &socks5ProxyRoundRobinDialer{proxyDialers: dialers, robin: robin}, nil
}

func toStringSlice(urls []*url.URL) []string {
	s := make([]string, len(urls))
	for i, u := range urls {
		s[i] = u.String()
	}
	return s
}
