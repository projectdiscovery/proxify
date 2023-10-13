package proxify

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/armon/go-socks5"
	"github.com/haxii/fastproxy/bufiopool"
	"github.com/haxii/fastproxy/superproxy"
	"github.com/projectdiscovery/dsl"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/martian/v3"
	martianlog "github.com/projectdiscovery/martian/v3/log"
	"github.com/projectdiscovery/proxify/pkg/certs"
	"github.com/projectdiscovery/proxify/pkg/logger"
	"github.com/projectdiscovery/proxify/pkg/logger/elastic"
	"github.com/projectdiscovery/proxify/pkg/logger/kafka"
	"github.com/projectdiscovery/proxify/pkg/types"
	"github.com/projectdiscovery/proxify/pkg/util"
	rbtransport "github.com/projectdiscovery/roundrobin/transport"
	"github.com/projectdiscovery/tinydns"
	errorutil "github.com/projectdiscovery/utils/errors"
	"golang.org/x/net/proxy"
)

type OnRequestFunc func(req *http.Request, ctx *martian.Context) error
type OnResponseFunc func(resp *http.Response, ctx *martian.Context) error

type Options struct {
	DumpRequest                 bool
	DumpResponse                bool
	OutputJsonl                 bool
	MaxSize                     int
	Verbosity                   types.Verbosity
	CertCacheSize               int
	Directory                   string
	ListenAddrHTTP              string
	ListenAddrSocks5            string
	OutputDirectory             string
	OutputFile                  string
	RequestDSL                  []string
	ResponseDSL                 []string
	UpstreamHTTPProxies         []string
	UpstreamSock5Proxies        []string
	ListenDNSAddr               string
	DNSMapping                  string
	DNSFallbackResolver         string
	RequestMatchReplaceDSL      []string
	ResponseMatchReplaceDSL     []string
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
	httpProxy    *martian.Proxy
	socks5proxy  *socks5.Server
	socks5tunnel *superproxy.SuperProxy
	bufioPool    *bufiopool.Pool
	tinydns      *tinydns.TinyDNS
	rbhttp       *rbtransport.RoundTransport
	rbsocks5     *rbtransport.RoundTransport
}

// ModifyRequest
func (p *Proxy) ModifyRequest(req *http.Request) error {
	ctx := martian.NewContext(req)
	// disable upgrading http connections to https by default
	ctx.Session().MarkInsecure()
	// setup passthrought and hijack here
	userData := types.UserData{
		ID:   ctx.ID(),
		Host: req.Host,
	}

	// If callbacks are given use them (for library use cases)
	if p.options.OnRequestCallback != nil {
		return p.options.OnRequestCallback(req, ctx)
	}

	for _, expr := range p.options.RequestDSL {
		if !userData.Match {
			m, _ := util.HTTPRequesToMap(req)
			v, err := dsl.EvalExpr(expr, m)
			if err != nil {
				gologger.Warning().Msgf("Could not evaluate request dsl: %s\n", err)
			}
			userData.Match = err == nil && v.(bool)
		}
	}
	ctx.Set("user-data", userData)

	// perform match and replace
	if len(p.options.RequestMatchReplaceDSL) != 0 {
		_ = p.MatchReplaceRequest(req)
	}
	_ = p.logger.LogRequest(req, userData)
	return nil
}

// ModifyResponse
func (p *Proxy) ModifyResponse(resp *http.Response) error {
	ctx := martian.NewContext(resp.Request)
	var userData *types.UserData
	if w, ok := ctx.Get("user-data"); ok {
		if data, ok2 := w.(types.UserData); ok2 {
			userData = &data
		}
	}
	if userData == nil {
		gologger.Error().Msgf("something went wrong got response without userData")
		// pass empty struct to avoid panic
		userData = &types.UserData{}
	}
	userData.HasResponse = true

	// If callbacks are given use them (for library use cases)
	if p.options.OnResponseCallback != nil {
		return p.options.OnResponseCallback(resp, ctx)
	}

	// TODO: match in request seems to be seperate from response
	// but share same `Match` value. investigate this
	matchStatus := false
	for _, expr := range p.options.ResponseDSL {
		if !matchStatus {
			m, _ := util.HTTPResponseToMap(resp)
			v, err := dsl.EvalExpr(expr, m)
			if err != nil {
				gologger.Warning().Msgf("Could not evaluate response dsl: %s\n", err)
			}
			matchStatus = err == nil && v.(bool)
		}
	}
	userData.Match = matchStatus
	// perform match and replace
	if len(p.options.ResponseMatchReplaceDSL) != 0 {
		_ = p.MatchReplaceResponse(resp)
	}
	_ = p.logger.LogResponse(resp, *userData)
	if resp.StatusCode == 301 || resp.StatusCode == 302 {
		// set connection close header
		// close connection if redirected to different host
		if loc, err := resp.Location(); err == nil {
			if loc.Host == resp.Request.Host {
				// if same host redirect do not close connection
				return nil
			}
		}
		resp.Close = true
	}
	return nil
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
	if p.httpProxy != nil {
		p.httpProxy.TLSPassthroughFunc = func(req *http.Request) bool {
			// Skip MITM for hosts that are in pass-through list
			return util.MatchAnyRegex(p.options.PassThrough, req.Host)
		}

		p.httpProxy.SetRequestModifier(p)
		p.httpProxy.SetResponseModifier(p)

		l, err := net.Listen("tcp", p.options.ListenAddrHTTP)
		if err != nil {
			gologger.Fatal().Msgf("failed to setup listener got %v", err)
		}
		// serve web page to download ca cert
		go func() {
			//fmt.Println("web page listening on", p.options.ListenAddrHTTP+"/")
			gologger.Fatal().Msgf("%v", serveWebPage(l))
		}()

		go func() {
			//fmt.Println("proxy listening on", p.options.ListenAddrHTTP)
			gologger.Fatal().Msgf("%v", p.httpProxy.Serve(l))
		}()
	}

	// socks5 proxy
	if p.socks5proxy != nil {
		if p.httpProxy != nil {
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

// setupHTTPProxy configures proxy with settings
func (p *Proxy) setupHTTPProxy() error {
	hp := martian.NewProxy()
	hp.Miscellaneous.SetH1ConnectionHeader = true
	hp.Miscellaneous.StripProxyHeaders = true
	hp.Miscellaneous.IgnoreWebSocketError = true
	rt, err := p.getRoundTripper()
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("failed to setup transport")
	}
	hp.SetRoundTripper(rt)
	dialContextFunc := func(ctx context.Context, a, b string) (net.Conn, error) {
		return p.Dialer.Dial(ctx, a, b)
	}
	hp.SetDialContext(dialContextFunc)
	hp.SetMITM(certs.GetMitMConfig())
	p.httpProxy = hp
	return nil
}

// getRoundTripper returns RoundTripper configured with options
func (p *Proxy) getRoundTripper() (http.RoundTripper, error) {
	roundtrip := &http.Transport{
		MaxIdleConnsPerHost: -1,
		MaxIdleConns:        0,
		MaxConnsPerHost:     0,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS10,
			InsecureSkipVerify: true,
		},
	}

	if len(p.options.UpstreamHTTPProxies) > 0 {
		roundtrip = &http.Transport{Proxy: func(req *http.Request) (*url.URL, error) {
			return url.Parse(p.rbhttp.Next())
		}, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	} else if len(p.options.UpstreamSock5Proxies) > 0 {
		// for each socks5 proxy create a dialer
		socks5Dialers := make(map[string]proxy.Dialer)
		for _, socks5proxy := range p.options.UpstreamSock5Proxies {
			dialer, err := proxy.SOCKS5("tcp", socks5proxy, nil, proxy.Direct)
			if err != nil {
				return nil, err
			}
			socks5Dialers[socks5proxy] = dialer
		}
		roundtrip = &http.Transport{Dial: func(network, addr string) (net.Conn, error) {
			// lookup next dialer
			socks5Proxy := p.rbsocks5.Next()
			socks5Dialer := socks5Dialers[socks5Proxy]
			// use it to perform the request
			return socks5Dialer.Dial(network, addr)
		}, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	return roundtrip, nil
}

func (p *Proxy) Stop() {
	// p.httpProxy.Close()
}

func NewProxy(options *Options) (*Proxy, error) {

	switch options.Verbosity {
	case types.VerbositySilent:
		martianlog.SetLevel(martianlog.Silent)
	case types.VerbosityVerbose:
		martianlog.SetLevel(martianlog.Info)
	case types.VerbosityVeryVerbose:
		martianlog.SetLevel(martianlog.Debug)
	default:
		martianlog.SetLevel(martianlog.Error)
	}

	logger := logger.NewLogger(&logger.OptionsLogger{
		Verbosity:    options.Verbosity,
		OutputFile:   options.OutputFile,
		OutputFolder: options.OutputDirectory,
		DumpRequest:  options.DumpRequest,
		DumpResponse: options.DumpResponse,
		OutputJsonl:  options.OutputJsonl,
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
		var err error
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
		logger:   logger,
		options:  options,
		Dialer:   dialer,
		tinydns:  tdns,
		rbhttp:   rbhttp,
		rbsocks5: rbsocks5,
	}

	if err := proxy.setupHTTPProxy(); err != nil {
		return nil, err
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

func serveWebPage(l net.Listener) error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current working directory: %v", err)
	}
	absStaticDirPath := strings.Join([]string{strings.Split(cwd, "cmd")[0], "static"}, "/")

	mux := http.NewServeMux()
	serveStatic := http.FileServer(http.Dir(absStaticDirPath))
	mux.Handle("/", serveStatic)
	// download ca cert
	mux.HandleFunc("/cacert", func(w http.ResponseWriter, r *http.Request) {
		buffer, err := certs.GetRawCA()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			gologger.Error().Msgf("failed to get raw CA: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename=\"cacert.pem\"")
		w.Write(buffer.Bytes())
	})

	server := &http.Server{
		Handler: mux,
	}
	return server.Serve(l)
}
