package proxify

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	rbtransport "github.com/Mzack9999/roundrobin/transport"
	"github.com/armon/go-socks5"
	"github.com/elazarl/goproxy"
	"github.com/haxii/fastproxy/bufiopool"
	"github.com/haxii/fastproxy/superproxy"
	"github.com/projectdiscovery/dsl"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/proxify/pkg/certs"
	"github.com/projectdiscovery/proxify/pkg/logger"
	"github.com/projectdiscovery/proxify/pkg/logger/elastic"
	"github.com/projectdiscovery/proxify/pkg/logger/kafka"
	"github.com/projectdiscovery/proxify/pkg/types"
	"github.com/projectdiscovery/proxify/pkg/util"
	"github.com/projectdiscovery/tinydns"
	"github.com/rs/xid"
	"golang.org/x/net/proxy"
)

type OnRequestFunc func(*http.Request, *goproxy.ProxyCtx) (*http.Request, *http.Response)
type OnResponseFunc func(*http.Response, *goproxy.ProxyCtx) *http.Response
type OnConnectFunc func(string, *goproxy.ProxyCtx) (*goproxy.ConnectAction, string)

type Options struct {
	DumpRequest                 bool
	DumpResponse                bool
	MaxSize                     int
	Verbosity                   types.Verbosity
	CertCacheSize               int
	Directory                   string
	ListenAddrHTTP              string
	ListenAddrSocks5            string
	OutputDirectory             string
	RequestDSL                  []string
	ResponseDSL                 []string
	UpstreamHTTPProxies         []string
	UpstreamSock5Proxies        []string
	ListenDNSAddr               string
	DNSMapping                  string
	DNSFallbackResolver         string
	RequestMatchReplaceDSL      []string
	ResponseMatchReplaceDSL     []string
	OnConnectHTTPCallback       OnConnectFunc
	OnConnectHTTPSCallback      OnConnectFunc
	OnRequestCallback           OnRequestFunc
	OnResponseCallback          OnResponseFunc
	Deny                        []string
	Allow                       []string
	PassThrough                 []string
	UpstreamProxyRequestsNumber int
	Elastic                     *elastic.Options
	Kafka                       *kafka.Options
}

type Proxy struct {
	Dialer       *fastdialer.Dialer
	options      *Options
	logger       *logger.Logger
	certs        *certs.Manager
	httpproxy    *goproxy.ProxyHttpServer
	socks5proxy  *socks5.Server
	socks5tunnel *superproxy.SuperProxy
	bufioPool    *bufiopool.Pool
	tinydns      *tinydns.TinyDNS
	rbhttp       *rbtransport.RoundTransport
	rbsocks5     *rbtransport.RoundTransport
}

func (p *Proxy) OnRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	var userdata types.UserData
	if ctx.UserData != nil {
		userdata = ctx.UserData.(types.UserData)
	} else {
		userdata.Host = req.URL.Host
	}

	// check dsl
	for _, expr := range p.options.RequestDSL {
		if !userdata.Match {
			m, _ := util.HTTPRequesToMap(req)
			v, err := dsl.EvalExpr(expr, m)
			if err != nil {
				gologger.Warning().Msgf("Could not evaluate request dsl: %s\n", err)
			}
			userdata.Match = err == nil && v.(bool)
		}
	}

	id := xid.New().String()
	userdata.ID = id

	// perform match and replace
	if len(p.options.RequestMatchReplaceDSL) != 0 {
		_ = p.MatchReplaceRequest(req)
	}

	_ = p.logger.LogRequest(req, userdata)
	ctx.UserData = userdata

	return req, nil
}

func (p *Proxy) OnResponse(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	userdata := ctx.UserData.(types.UserData)
	userdata.HasResponse = true
	for _, expr := range p.options.ResponseDSL {
		if !userdata.Match {
			m, _ := util.HTTPResponseToMap(resp)
			v, err := dsl.EvalExpr(expr, m)
			if err != nil {
				gologger.Warning().Msgf("Could not evaluate response dsl: %s\n", err)
			}
			userdata.Match = err == nil && v.(bool)
		}
	}

	// perform match and replace
	if len(p.options.ResponseMatchReplaceDSL) != 0 {
		_ = p.MatchReplaceResponse(resp)
	}

	_ = p.logger.LogResponse(resp, userdata)
	ctx.UserData = userdata
	return resp
}

func (p *Proxy) OnConnectHTTP(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	if util.MatchAnyRegex(p.options.PassThrough, host) {
		return goproxy.OkConnect, host
	}
	ctx.UserData = types.UserData{Host: host}
	return goproxy.HTTPMitmConnect, host
}

func (p *Proxy) OnConnectHTTPS(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	if util.MatchAnyRegex(p.options.PassThrough, host) {
		return goproxy.OkConnect, host
	}
	ctx.UserData = types.UserData{Host: host}
	return goproxy.MitmConnect, host
}

// MatchReplaceRequest strings or regex
func (p *Proxy) MatchReplaceRequest(req *http.Request) error {
	// lazy mode - dump request
	reqdump, err := httputil.DumpRequest(req, true)
	if err != nil {
		return err
	}

	// lazy mode - ninja level - elaborate
	m := make(map[string]interface{})
	m["request"] = string(reqdump)
	for _, expr := range p.options.RequestMatchReplaceDSL {
		v, err := dsl.EvalExpr(expr, m)
		if err != nil {
			return err
		}
		m["request"] = fmt.Sprint(v)
	}

	reqbuffer := fmt.Sprint(m["request"])
	// lazy mode - epic level - rebuild
	bf := bufio.NewReader(strings.NewReader(reqbuffer))
	requestNew, err := http.ReadRequest(bf)
	if err != nil {
		return err
	}
	// closes old body to allow memory reuse
	req.Body.Close()

	// override original properties
	req.Method = requestNew.Method
	req.Header = requestNew.Header
	req.Body = requestNew.Body
	req.URL = requestNew.URL
	return nil
}

// MatchReplaceRequest strings or regex
func (p *Proxy) MatchReplaceResponse(resp *http.Response) error {
	// Set Content-Length to zero to allow automatic calculation
	resp.ContentLength = 0

	// lazy mode - dump request
	respdump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return err
	}

	// lazy mode - ninja level - elaborate
	m := make(map[string]interface{})
	m["response"] = string(respdump)
	for _, expr := range p.options.ResponseMatchReplaceDSL {
		v, err := dsl.EvalExpr(expr, m)

		if err != nil {
			return err
		}
		m["response"] = fmt.Sprint(v)
	}

	respbuffer := fmt.Sprint(m["response"])
	// lazy mode - epic level - rebuild
	bf := bufio.NewReader(strings.NewReader(respbuffer))
	responseNew, err := http.ReadResponse(bf, nil)
	if err != nil {
		return err
	}

	// closes old body to allow memory reuse
	resp.Body.Close()
	resp.Header = responseNew.Header
	resp.Body = responseNew.Body
	resp.ContentLength = responseNew.ContentLength
	return nil
}

func (p *Proxy) Run() error {
	if p.tinydns != nil {
		go func() {
			if err := p.tinydns.Run(); err != nil {
				gologger.Warning().Msgf("Could not start dns server: %s\n", err)
			}
		}()
	}

	// http proxy
	if p.httpproxy != nil {
		if len(p.options.UpstreamHTTPProxies) > 0 {
			p.httpproxy.Tr = &http.Transport{Proxy: func(req *http.Request) (*url.URL, error) {
				return url.Parse(p.rbhttp.Next())
			}, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
			p.httpproxy.ConnectDial = nil
		} else if len(p.options.UpstreamSock5Proxies) > 0 {
			// for each socks5 proxy create a dialer
			socks5Dialers := make(map[string]proxy.Dialer)
			for _, socks5proxy := range p.options.UpstreamSock5Proxies {
				dialer, err := proxy.SOCKS5("tcp", socks5proxy, nil, proxy.Direct)
				if err != nil {
					return err
				}
				socks5Dialers[socks5proxy] = dialer
			}
			p.httpproxy.Tr = &http.Transport{Dial: func(network, addr string) (net.Conn, error) {
				// lookup next dialer
				socks5Proxy := p.rbsocks5.Next()
				socks5Dialer := socks5Dialers[socks5Proxy]
				// use it to perform the request
				return socks5Dialer.Dial(network, addr)
			}, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
			p.httpproxy.ConnectDial = nil
		} else {
			p.httpproxy.Tr.DialContext = p.Dialer.Dial
		}
		onConnectHTTP := p.OnConnectHTTP
		if p.options.OnConnectHTTPCallback != nil {
			onConnectHTTP = p.options.OnConnectHTTPCallback
		}
		onConnectHTTPS := p.OnConnectHTTPS
		if p.options.OnConnectHTTPSCallback != nil {
			onConnectHTTPS = p.options.OnConnectHTTPSCallback
		}
		onRequest := p.OnRequest
		if p.options.OnRequestCallback != nil {
			onRequest = p.options.OnRequestCallback
		}
		onResponse := p.OnResponse
		if p.options.OnResponseCallback != nil {
			onResponse = p.options.OnResponseCallback
		}
		p.httpproxy.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile("^.*:80$"))).HandleConnectFunc(onConnectHTTP)
		p.httpproxy.OnRequest(goproxy.ReqHostMatches(regexp.MustCompile("^.*:443$"))).HandleConnectFunc(onConnectHTTPS)
		// catch all
		p.httpproxy.OnRequest().HandleConnectFunc(onConnectHTTPS)
		p.httpproxy.OnRequest().DoFunc(onRequest)
		p.httpproxy.OnResponse().DoFunc(onResponse)

		// Serve the certificate when the user makes requests to /proxify
		p.httpproxy.OnRequest(goproxy.DstHostIs("proxify")).DoFunc(
			func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
				if r.URL.Path != "/cacert.crt" {
					return r, goproxy.NewResponse(r, "text/plain", 404, "Invalid path given")
				}

				_, ca := p.certs.GetCA()
				reader := bytes.NewReader(ca)

				header := http.Header{}
				header.Set("Content-Type", "application/pkix-cert")
				resp := &http.Response{
					Request:          r,
					TransferEncoding: r.TransferEncoding,
					Header:           header,
					StatusCode:       200,
					Status:           http.StatusText(200),
					ContentLength:    int64(reader.Len()),
					Body:             io.NopCloser(reader),
				}
				return r, resp
			},
		)
		go http.ListenAndServe(p.options.ListenAddrHTTP, p.httpproxy) // nolint
	}

	// socks5 proxy
	if p.socks5proxy != nil {
		if p.httpproxy != nil {
			httpProxyIP, httpProxyPort, err := net.SplitHostPort(p.options.ListenAddrHTTP)
			if err != nil {
				return err
			}
			httpProxyPortUint, err := strconv.ParseUint(httpProxyPort, 10, 16)
			if err != nil {
				return err
			}
			p.socks5tunnel, err = superproxy.NewSuperProxy(httpProxyIP, uint16(httpProxyPortUint), superproxy.ProxyTypeHTTP, "", "", "")
			if err != nil {
				return err
			}
			p.bufioPool = bufiopool.New(4096, 4096)
		}

		return p.socks5proxy.ListenAndServe("tcp", p.options.ListenAddrSocks5)
	}

	return nil
}

func (p *Proxy) Stop() {

}

func NewProxy(options *Options) (*Proxy, error) {
	certs, err := certs.New(&certs.Options{
		CacheSize: options.CertCacheSize,
		Directory: options.Directory,
	})
	if err != nil {
		return nil, err
	}

	var httpproxy *goproxy.ProxyHttpServer
	if options.ListenAddrHTTP != "" {
		httpproxy = goproxy.NewProxyHttpServer()
		if options.Verbosity <= types.VerbositySilent {
			httpproxy.Logger = log.New(io.Discard, "", log.Ltime|log.Lshortfile)
		} else if options.Verbosity >= types.VerbosityVerbose {
			httpproxy.Verbose = true
		} else {
			httpproxy.Verbose = false
		}
	}

	ca, _ := certs.GetCA()
	goproxy.GoproxyCa = ca
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: certs.TLSConfigFromCA()}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: certs.TLSConfigFromCA()}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: certs.TLSConfigFromCA()}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: certs.TLSConfigFromCA()}

	logger := logger.NewLogger(&logger.OptionsLogger{
		Verbosity:    options.Verbosity,
		OutputFolder: options.OutputDirectory,
		DumpRequest:  options.DumpRequest,
		DumpResponse: options.DumpResponse,
		MaxSize:      options.MaxSize,
		Elastic:      options.Elastic,
		Kafka:        options.Kafka,
	})

	var tdns *tinydns.TinyDNS

	fastdialerOptions := fastdialer.DefaultOptions
	fastdialerOptions.EnableFallback = true
	fastdialerOptions.Deny = options.Deny
	fastdialerOptions.Allow = options.Allow
	if options.ListenDNSAddr != "" {
		dnsmapping := make(map[string]*tinydns.DnsRecord)
		for _, record := range strings.Split(options.DNSMapping, ",") {
			data := strings.Split(record, ":")
			if len(data) != 2 {
				continue
			}
			dnsmapping[data[0]] = &tinydns.DnsRecord{A: []string{data[1]}}
		}
		tdns, err = tinydns.New(&tinydns.Options{
			ListenAddress:   options.ListenDNSAddr,
			Net:             "udp",
			UpstreamServers: []string{options.DNSFallbackResolver},
			DnsRecords:      dnsmapping,
		})
		if err != nil {
			return nil, err
		}
		fastdialerOptions.BaseResolvers = []string{"127.0.0.1" + options.ListenDNSAddr}
	}
	dialer, err := fastdialer.NewDialer(fastdialerOptions)
	if err != nil {
		return nil, err
	}

	var rbhttp, rbsocks5 *rbtransport.RoundTransport
	if len(options.UpstreamHTTPProxies) > 0 {
		rbhttp, err = rbtransport.NewWithOptions(options.UpstreamProxyRequestsNumber, options.UpstreamHTTPProxies...)
		if err != nil {
			return nil, err
		}
	}
	if len(options.UpstreamSock5Proxies) > 0 {
		rbsocks5, err = rbtransport.NewWithOptions(options.UpstreamProxyRequestsNumber, options.UpstreamSock5Proxies...)
		if err != nil {
			return nil, err
		}
	}

	proxy := &Proxy{
		httpproxy: httpproxy,
		certs:     certs,
		logger:    logger,
		options:   options,
		Dialer:    dialer,
		tinydns:   tdns,
		rbhttp:    rbhttp,
		rbsocks5:  rbsocks5,
	}

	var socks5proxy *socks5.Server
	if options.ListenAddrSocks5 != "" {
		socks5Config := &socks5.Config{
			Dial: proxy.httpTunnelDialer,
		}
		if options.Verbosity <= types.VerbositySilent {
			socks5Config.Logger = log.New(io.Discard, "", log.Ltime|log.Lshortfile)
		}
		socks5proxy, err = socks5.New(socks5Config)
		if err != nil {
			return nil, err
		}
	}

	proxy.socks5proxy = socks5proxy

	return proxy, nil
}

func (p *Proxy) httpTunnelDialer(ctx context.Context, network, addr string) (net.Conn, error) {
	return p.socks5tunnel.MakeTunnel(nil, nil, p.bufioPool, addr)
}
