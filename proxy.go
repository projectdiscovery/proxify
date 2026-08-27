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
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

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
	"github.com/projectdiscovery/utils/errkit"
	readerUtil "github.com/projectdiscovery/utils/reader"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"github.com/things-go/go-socks5"
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
	ListenAddrSOCKS5            string
	OutputDirectory             string
	OutputFile                  string
	OutputFormat                string
	OutputHar                   string
	RequestDSL                  []string
	ResponseDSL                 []string
	UpstreamHTTPProxies         []string
	UpstreamSOCKS5Proxies       []string
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
	socks5Proxy  *socks5.Server
	socks5Tunnel *superproxy.SuperProxy
	bufioPool    *bufiopool.Pool
	tinyDNS      *tinydns.TinyDNS
	rbHTTP       *rbtransport.RoundTransport
	rbSOCKS5     *rbtransport.RoundTransport
	proxifyMux   *http.ServeMux // serve banner page and static files
	listenAddr   string
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
		OutputFormat: options.OutputFormat,
		OutputFolder: options.OutputDirectory,
		OutputHar:    options.OutputHar,
		DumpRequest:  options.DumpRequest,
		DumpResponse: options.DumpResponse,
		MaxSize:      options.MaxSize,
		Elastic:      options.Elastic,
		Kafka:        options.Kafka,
	})

	var tDNS *tinydns.TinyDNS

	fastdialerOptions := fastdialer.DefaultOptions
	fastdialerOptions.EnableFallback = true
	fastdialerOptions.Deny = options.Deny
	fastdialerOptions.Allow = options.Allow
	if options.ListenDNSAddr != "" {
		dnsMapping := make(map[string]*tinydns.DnsRecord)
		for _, record := range strings.Split(options.DNSMapping, ",") {
			data := strings.Split(record, ":")
			if len(data) != 2 {
				continue
			}
			dnsMapping[data[0]] = &tinydns.DnsRecord{A: []string{data[1]}}
		}
		var err error
		tDNS, err = tinydns.New(&tinydns.Options{
			ListenAddress:   options.ListenDNSAddr,
			Net:             "udp",
			UpstreamServers: []string{options.DNSFallbackResolver},
			DnsRecords:      dnsMapping,
		})
		if err != nil {
			return nil, err
		}
		fastdialerOptions.BaseResolvers = []string{"127.0.0.1" + options.ListenDNSAddr}
	}

	if len(options.UpstreamHTTPProxies) > 0 {
		proxyDialer, err := newHTTPProxyRoundRobinDialer(options.UpstreamHTTPProxies)
		if err != nil {
			return nil, err
		}
		fastdialerOptions.ProxyDialer = &proxyDialer
	}

	if len(options.UpstreamSOCKS5Proxies) > 0 {
		dialer, err := newSOCKS5ProxyRoundRobinDialer(options.UpstreamSOCKS5Proxies)
		if err != nil {
			return nil, err
		}
		fastdialerOptions.ProxyDialer = &dialer
	}

	dialer, err := fastdialer.NewDialer(fastdialerOptions)
	if err != nil {
		return nil, err
	}

	var rbHTTP, rbSOCKS5 *rbtransport.RoundTransport
	if len(options.UpstreamHTTPProxies) > 0 {
		rbHTTP, err = rbtransport.NewWithOptions(options.UpstreamProxyRequestsNumber, options.UpstreamHTTPProxies...)
		if err != nil {
			return nil, err
		}
	}
	if len(options.UpstreamSOCKS5Proxies) > 0 {
		rbSOCKS5, err = rbtransport.NewWithOptions(options.UpstreamProxyRequestsNumber, options.UpstreamSOCKS5Proxies...)
		if err != nil {
			return nil, err
		}
	}
	pMux, err := getProxifyServerMux()
	if err != nil {
		return nil, err
	}

	proxy := &Proxy{
		logger:     logger,
		options:    options,
		Dialer:     dialer,
		tinyDNS:    tDNS,
		rbHTTP:     rbHTTP,
		rbSOCKS5:   rbSOCKS5,
		proxifyMux: pMux,
	}

	if err := proxy.setupHTTPProxy(); err != nil {
		return nil, err
	}

	var socks5Proxy *socks5.Server
	if options.ListenAddrSOCKS5 != "" {
		if options.Verbosity <= types.VerbositySilent {
			socks5Proxy = socks5.NewServer(
				socks5.WithLogger(socks5.NewLogger(log.New(io.Discard, "", log.Ltime|log.Lshortfile))),
				socks5.WithDial(proxy.httpTunnelDialer),
			)
		} else {
			socks5Proxy = socks5.NewServer(
				socks5.WithDial(proxy.httpTunnelDialer),
			)
		}
	}

	proxy.socks5Proxy = socks5Proxy

	return proxy, nil
}

// ModifyRequest
func (p *Proxy) ModifyRequest(req *http.Request) error {
	// // Set Content-Length to zero to allow automatic calculation
	req.ContentLength = -1

	ctx := martian.NewContext(req)
	// disable upgrading http connections to https by default
	ctx.Session().MarkInsecure()
	// setup passthrought and hijack here
	userData := types.UserData{
		ID:   ctx.ID(),
		Host: req.Host,
	}

	if stringsutil.EqualFoldAny(req.Host, "proxify", "proxify:443", "proxify:80", p.listenAddr) {
		// hijack if this is true
		return p.hijackNServe(req, ctx)
	}

	// If callbacks are given use them (for library use cases)
	if p.options.OnRequestCallback != nil {
		return p.options.OnRequestCallback(req, ctx)
	}

	boolSlice := []bool{}
	for _, expr := range p.options.RequestDSL {
		m, _ := util.HTTPRequestToMap(req)
		v, err := dsl.EvalExpr(expr, m)
		if err != nil {
			gologger.Warning().Msgf("Could not evaluate request dsl: %s\n", err)
		}
		boolSlice = append(boolSlice, err == nil && v.(bool))
	}
	// evaluate bool array to get match status
	if len(boolSlice) > 0 {
		tmp := util.EvalBoolSlice(boolSlice)
		userData.Match = &tmp
	}

	ctx.Set("user-data", userData)

	// perform match and replace
	if len(p.options.RequestMatchReplaceDSL) != 0 {
		_ = p.MatchReplaceRequest(req)
	}
	p.removeBrEncoding(req)
	_ = p.logger.LogRequest(req, userData)
	return nil
}

func (*Proxy) removeBrEncoding(req *http.Request) {
	encodings := strings.Split(strings.ReplaceAll(req.Header.Get("Accept-Encoding"), " ", ""), ",")
	encodings = sliceutil.PruneEqual(encodings, "br")
	req.Header.Set("Accept-Encoding", strings.Join(encodings, ", "))

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
		gologger.Warning().Msgf("something went wrong got response without userData")
		// pass empty struct to avoid panic
		userData = &types.UserData{}
	}
	userData.HasResponse = true

	// if content-length is zero and remove header
	if resp.ContentLength == 0 {
		resp.Header.Del("Content-Length")
	}

	// If callbacks are given use them (for library use cases)
	if p.options.OnResponseCallback != nil {
		return p.options.OnResponseCallback(resp, ctx)
	}

	boolSlice := []bool{}
	for _, expr := range p.options.ResponseDSL {
		m, _ := util.HTTPResponseToMap(resp)
		v, err := dsl.EvalExpr(expr, m)
		if err != nil {
			gologger.Warning().Msgf("Could not evaluate response dsl: %s\n", err)
		}
		boolSlice = append(boolSlice, err == nil && v.(bool))
	}
	if len(boolSlice) > 0 {
		tmp := util.EvalBoolSlice(boolSlice)
		// finalize
		if userData.Match != nil {
			tmp = *userData.Match && tmp
		}
		userData.Match = &tmp
	}
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
	_ = req.Body.Close()

	// override original properties
	req.Method = requestNew.Method
	req.Header = requestNew.Header
	req.Body = requestNew.Body
	req.URL = requestNew.URL
	return nil
}

// MatchReplaceRequest strings or regex
func (p *Proxy) MatchReplaceResponse(resp *http.Response) error {
	// // Set Content-Length to zero to allow automatic calculation
	resp.ContentLength = -1

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
	_ = resp.Body.Close()
	resp.Header = responseNew.Header
	resp.Body, err = readerUtil.NewReusableReadCloser(responseNew.Body)
	if err != nil {
		return err
	}
	if resp.ContentLength == 0 {
		resp.Header.Del("Content-Length")
	}
	// resp.ContentLength = responseNew.ContentLength
	return nil
}

func (p *Proxy) Run() error {
	var wg sync.WaitGroup

	if p.tinyDNS != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := p.tinyDNS.Run(); err != nil {
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
		p.listenAddr = l.Addr().String()
		wg.Add(1)
		go func() {
			defer wg.Done()
			gologger.Fatal().Msgf("%v", p.httpProxy.Serve(l))
		}()
	}

	// socks5 proxy
	if p.socks5Proxy != nil {
		if p.httpProxy != nil {
			httpProxyIP, httpProxyPort, err := net.SplitHostPort(p.options.ListenAddrHTTP)
			if err != nil {
				return err
			}
			httpProxyPortUint, err := strconv.ParseUint(httpProxyPort, 10, 16)
			if err != nil {
				return err
			}
			p.socks5Tunnel, err = superproxy.NewSuperProxy(httpProxyIP, uint16(httpProxyPortUint), superproxy.ProxyTypeHTTP, "", "", "")
			if err != nil {
				return err
			}
			p.bufioPool = bufiopool.New(4096, 4096)
		}

		wg.Add(1)
		go func() {
			defer wg.Done()

			gologger.Fatal().Msgf("%v", p.socks5Proxy.ListenAndServe("tcp", p.options.ListenAddrSOCKS5))
		}()
	}

	wg.Wait()
	return nil
}

func (p *Proxy) Stop() {
	p.logger.Close()
}

// setupHTTPProxy configures proxy with settings
func (p *Proxy) setupHTTPProxy() error {
	hp := martian.NewProxy()
	hp.Miscellaneous.SetH1ConnectionHeader = true
	hp.Miscellaneous.StripProxyHeaders = true
	hp.Miscellaneous.IgnoreWebSocketError = true
	rt, err := p.getRoundTripper()
	if err != nil {
		return errkit.Wrap(err, "failed to setup transport")
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
			return url.Parse(p.rbHTTP.Next())
		}, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	if len(p.options.UpstreamSOCKS5Proxies) > 0 {
		// for each socks5 proxy create a dialer
		socks5Dialers := make(map[string]proxy.Dialer)
		for _, socks5Proxy := range p.options.UpstreamSOCKS5Proxies {
			dialer, err := proxy.SOCKS5("tcp", socks5Proxy, nil, proxy.Direct)
			if err != nil {
				return nil, err
			}
			socks5Dialers[socks5Proxy] = dialer
		}
		roundtrip = &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			socks5Proxy := p.rbSOCKS5.Next()
			socks5Dialer := socks5Dialers[socks5Proxy]
			if cd, ok := socks5Dialer.(proxy.ContextDialer); ok {
				return cd.DialContext(ctx, network, addr)
			}
			return socks5Dialer.Dial(network, addr)
		}, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	return roundtrip, nil
}

func (p *Proxy) httpTunnelDialer(ctx context.Context, network, addr string) (net.Conn, error) {
	return p.socks5Tunnel.MakeTunnel(nil, nil, p.bufioPool, addr)
}

func (p *Proxy) hijackNServe(req *http.Request, ctx *martian.Context) error {
	conn, brw, err := ctx.Session().Hijack()
	if err != nil {
		return err
	}
	defer func() {
		_ = conn.Close()
	}()
	rec := httptest.NewRecorder()
	p.proxifyMux.ServeHTTP(rec, req)
	resp := rec.Result()
	resp.Close = true
	if err := resp.Write(brw); err != nil {
		gologger.Warning().Msgf("failed to write response: %v", err)
	}
	if err := brw.Flush(); err != nil {
		gologger.Warning().Msgf("failed to flush buffer: %v", err)
	}
	return nil
}

func getProxifyServerMux() (*http.ServeMux, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get current working directory: %v", err)
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
			gologger.Warning().Msgf("failed to get raw CA: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment; filename=\"proxify.pem\"")
		if _, err := w.Write(buffer.Bytes()); err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			gologger.Warning().Msgf("failed to write raw CA: %v", err)
			return
		}
	})
	return mux, nil
}
