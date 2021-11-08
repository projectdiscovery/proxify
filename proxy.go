package proxify

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
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
	"github.com/projectdiscovery/mapsutil"
	"github.com/projectdiscovery/proxify/pkg/certs"
	"github.com/projectdiscovery/tinydns"
	"github.com/rs/xid"
	"golang.org/x/net/proxy"
)

type UserData struct {
	id          string
	match       bool
	hasResponse bool
	host        string
}

type OnRequestFunc func(*http.Request, *goproxy.ProxyCtx) (*http.Request, *http.Response)
type OnResponseFunc func(*http.Response, *goproxy.ProxyCtx) *http.Response
type OnConnectFunc func(string, *goproxy.ProxyCtx) (*goproxy.ConnectAction, string)

type Options struct {
	DumpRequest                 bool
	DumpResponse                bool
	Silent                      bool
	Verbose                     bool
	CertCacheSize               int
	Directory                   string
	ListenAddrHTTP              string
	ListenAddrSocks5            string
	OutputDirectory             string
	RequestDSL                  string
	ResponseDSL                 string
	UpstreamHTTPProxies         []string
	UpstreamSock5Proxies        []string
	ListenDNSAddr               string
	DNSMapping                  string
	DNSFallbackResolver         string
	RequestMatchReplaceDSL      string
	ResponseMatchReplaceDSL     string
	OnConnectHTTPCallback       OnConnectFunc
	OnConnectHTTPSCallback      OnConnectFunc
	OnRequestCallback           OnRequestFunc
	OnResponseCallback          OnResponseFunc
	Deny                        []string
	Allow                       []string
	UpstreamProxyRequestsNumber int
}

type Proxy struct {
	Dialer       *fastdialer.Dialer
	options      *Options
	logger       *Logger
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
	var userdata UserData
	if ctx.UserData != nil {
		userdata = ctx.UserData.(UserData)
	} else {
		userdata.host = req.URL.Host
	}

	// check dsl
	if p.options.RequestDSL != "" {
		m, _ := mapsutil.HTTPRequesToMap(req)
		v, err := dsl.EvalExpr(p.options.RequestDSL, m)
		userdata.match = err == nil && v.(bool)
	}

	id := xid.New().String()
	userdata.id = id

	// perform match and replace
	if p.options.RequestMatchReplaceDSL != "" {
		req = p.MatchReplaceRequest(req)
	}

	p.logger.LogRequest(req, userdata) //nolint
	ctx.UserData = userdata

	return req, nil
}

func (p *Proxy) OnResponse(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	userdata := ctx.UserData.(UserData)
	userdata.hasResponse = true
	if p.options.ResponseDSL != "" && !userdata.match {
		m, _ := mapsutil.HTTPResponseToMap(resp)
		v, err := dsl.EvalExpr(p.options.ResponseDSL, m)
		userdata.match = err == nil && v.(bool)
	}

	// perform match and replace
	if p.options.ResponseMatchReplaceDSL != "" {
		resp = p.MatchReplaceResponse(resp)
	}

	ctx.UserData = userdata
	return resp
}

func (p *Proxy) OnConnectHTTP(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	ctx.UserData = UserData{host: host}
	return goproxy.HTTPMitmConnect, host
}

func (p *Proxy) OnConnectHTTPS(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	ctx.UserData = UserData{host: host}
	return goproxy.MitmConnect, host
}

// MatchReplaceRequest strings or regex
func (p *Proxy) MatchReplaceRequest(req *http.Request) *http.Request {
	// lazy mode - dump request
	reqdump, err := httputil.DumpRequest(req, true)
	if err != nil {
		return req
	}

	// lazy mode - ninja level - elaborate
	m := make(map[string]interface{})
	m["request"] = string(reqdump)
	if v, err := dsl.EvalExpr(p.options.RequestMatchReplaceDSL, m); err != nil {
		return req
	} else {
		reqbuffer := fmt.Sprint(v)
		// lazy mode - epic level - rebuild
		bf := bufio.NewReader(strings.NewReader(reqbuffer))
		requestNew, err := http.ReadRequest(bf)
		if err != nil {
			return req
		}
		// closes old body to allow memory reuse
		req.Body.Close()
		return requestNew
	}
}

// MatchReplaceRequest strings or regex
func (p *Proxy) MatchReplaceResponse(resp *http.Response) *http.Response {
	// lazy mode - dump request
	respdump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return resp
	}

	// lazy mode - ninja level - elaborate
	m := make(map[string]interface{})
	m["response"] = string(respdump)
	if v, err := dsl.EvalExpr(p.options.ResponseMatchReplaceDSL, m); err != nil {
		return resp
	} else {
		respbuffer := fmt.Sprint(v)
		// lazy mode - epic level - rebuild
		bf := bufio.NewReader(strings.NewReader(respbuffer))
		responseNew, err := http.ReadResponse(bf, nil)
		if err != nil {
			return resp
		}

		// swap responses
		// closes old body to allow memory reuse
		resp.Body.Close()
		return responseNew
	}
}

func (p *Proxy) Run() error {
	if p.tinydns != nil {
		go p.tinydns.Run()
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
					Body:             ioutil.NopCloser(reader),
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
			httpProxyPortUint, err := strconv.ParseInt(httpProxyPort, 10, 32)
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
	log.Printf("%#v\n%d\n", options.UpstreamHTTPProxies, len(options.UpstreamHTTPProxies))
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
		if options.Silent {
			httpproxy.Logger = log.New(ioutil.Discard, "", log.Ltime|log.Lshortfile)
		} else if options.Verbose {
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

	logger := NewLogger(&OptionsLogger{
		Verbose:      options.Verbose,
		OutputFolder: options.OutputDirectory,
		DumpRequest:  options.DumpRequest,
		DumpResponse: options.DumpResponse,
	})

	var tdns *tinydns.TinyDNS

	fastdialerOptions := fastdialer.DefaultOptions
	fastdialerOptions.EnableFallback = true
	fastdialerOptions.Deny = options.Deny
	fastdialerOptions.Allow = options.Allow
	if options.ListenDNSAddr != "" {
		dnsmapping := make(map[string]string)
		for _, record := range strings.Split(options.DNSMapping, ",") {
			data := strings.Split(record, ":")
			if len(data) != 2 {
				continue
			}
			dnsmapping[data[0]] = data[1]
		}
		tdns = tinydns.NewTinyDNS(&tinydns.OptionsTinyDNS{
			ListenAddress:       options.ListenDNSAddr,
			Net:                 "udp",
			FallbackDNSResolver: options.DNSFallbackResolver,
			DomainToAddress:     dnsmapping,
		})
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
		if options.Silent {
			socks5Config.Logger = log.New(ioutil.Discard, "", log.Ltime|log.Lshortfile)
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
