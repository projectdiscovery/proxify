package proxify

import (
	"bufio"
	"bytes"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/elazarl/goproxy"
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
	Silent                  bool
	Verbose                 bool
	CertCacheSize           int
	Directory               string
	ListenAddr              string
	OutputDirectory         string
	RequestDSL              string
	ResponseDSL             string
	UpstreamHTTPProxy       string
	UpstreamSock5Proxy      string
	ListenDNSAddr           string
	DNSMapping              string
	DNSFallbackResolver     string
	RequestMatchReplaceDSL  string
	ResponseMatchReplaceDSL string
	OnConnectCallback       OnConnectFunc
	OnRequestCallback       OnRequestFunc
	OnResponseCallback      OnResponseFunc
}

type Proxy struct {
	Dialer    *fastdialer.Dialer
	options   *Options
	logger    *Logger
	certs     *certs.Manager
	httpproxy *goproxy.ProxyHttpServer
	tinydns   *tinydns.TinyDNS
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

	_ = p.logger.LogRequest(req, userdata)
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
		p.MatchReplaceResponse(resp)
	}

	_ = p.logger.LogResponse(resp, userdata)
	ctx.UserData = userdata
	return resp
}

func (p *Proxy) OnConnect(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
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
		reqbuffer := v.(string)

		// lazy mode - epic level - rebuild
		bf := bufio.NewReader(strings.NewReader(reqbuffer))
		requestNew, err := http.ReadRequest(bf)
		if err != nil {
			return req
		}

		requestNew.RequestURI = ""
		u, err := url.Parse(req.RequestURI)
		if err != nil {
			return req
		}
		requestNew.URL = u

		// swap requests
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
		respbuffer := v.(string)

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

	if p.options.UpstreamHTTPProxy != "" {
		p.httpproxy.Tr = &http.Transport{Proxy: func(req *http.Request) (*url.URL, error) {
			return url.Parse(p.options.UpstreamHTTPProxy)
		}}
		p.httpproxy.ConnectDial = p.httpproxy.NewConnectDialToProxy(p.options.UpstreamHTTPProxy)
	} else if p.options.UpstreamSock5Proxy != "" {
		dialer, err := proxy.SOCKS5("tcp", p.options.UpstreamSock5Proxy, nil, proxy.Direct)
		if err != nil {
			return err
		}
		p.httpproxy.Tr = &http.Transport{Dial: dialer.Dial}
		p.httpproxy.ConnectDial = nil
	} else {
		p.httpproxy.Tr.DialContext = p.Dialer.Dial
	}
	onConnect := p.OnConnect
	if p.options.OnConnectCallback != nil {
		onConnect = p.options.OnConnectCallback
	}
	onRequest := p.OnRequest
	if p.options.OnRequestCallback != nil {
		onRequest = p.options.OnRequestCallback
	}
	onResponse := p.OnResponse
	if p.options.OnResponseCallback != nil {
		onResponse = p.options.OnResponseCallback
	}
	p.httpproxy.OnRequest().HandleConnectFunc(onConnect)
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
	return http.ListenAndServe(p.options.ListenAddr, p.httpproxy)
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

	httpproxy := goproxy.NewProxyHttpServer()
	if options.Silent {
		httpproxy.Logger = log.New(ioutil.Discard, "", log.Ltime|log.Lshortfile)
	} else {
		httpproxy.Verbose = true
	}
	httpproxy.Verbose = false

	ca, _ := certs.GetCA()
	goproxy.GoproxyCa = ca
	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: certs.TLSConfigFromCA()}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: certs.TLSConfigFromCA()}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: certs.TLSConfigFromCA()}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: certs.TLSConfigFromCA()}

	logger := NewLogger(&OptionsLogger{
		Verbose:      options.Verbose,
		OutputFolder: options.OutputDirectory,
	})

	var tdns *tinydns.TinyDNS

	fastdialerOptions := fastdialer.DefaultOptions
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
	return &Proxy{httpproxy: httpproxy, certs: certs, logger: logger, options: options, Dialer: dialer, tinydns: tdns}, nil
}
