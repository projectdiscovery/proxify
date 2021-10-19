package runner

import (
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/proxify"
)

// Runner contains the internal logic of the program
type Runner struct {
	options *Options
	proxy   *proxify.Proxy
}

// NewRunner instance
func NewRunner(options *Options) (*Runner, error) {
	proxy, err := proxify.NewProxy(&proxify.Options{
		Silent:                      options.Silent,
		Directory:                   options.Directory,
		CertCacheSize:               options.CertCacheSize,
		Verbose:                     options.Verbose,
		ListenAddr:                  options.ListenAddr,
		OutputDirectory:             options.OutputDirectory,
		RequestDSL:                  options.RequestDSL,
		ResponseDSL:                 options.ResponseDSL,
		UpstreamHTTPProxies:         options.UpstreamHTTPProxies,
		UpstreamSock5Proxies:        options.UpstreamSocks5Proxies,
		ListenDNSAddr:               options.ListenDNSAddr,
		DNSMapping:                  options.DNSMapping,
		DNSFallbackResolver:         options.DNSFallbackResolver,
		RequestMatchReplaceDSL:      options.RequestMatchReplaceDSL,
		ResponseMatchReplaceDSL:     options.ResponseMatchReplaceDSL,
		DumpRequest:                 options.DumpRequest,
		DumpResponse:                options.DumpResponse,
		UpstreamProxyRequestsNumber: options.UpstreamProxyRequestsNumber,
	})
	if err != nil {
		return nil, err
	}
	return &Runner{options: options, proxy: proxy}, nil
}

// Run polling and notification
func (r *Runner) Run() error {
	// configuration summary
	gologger.Print().Msgf("Proxy Listening on %s\n", r.options.ListenAddr)
	if r.options.OutputDirectory != "" {
		gologger.Print().Msgf("Saving traffic to %s\n", r.options.OutputDirectory)
	}

	if len(r.options.UpstreamHTTPProxies) > 0 {
		gologger.Print().Msgf("Using upstream HTTP proxies: %s\n", strings.Join(r.options.UpstreamHTTPProxies, ","))
	} else if len(r.options.UpstreamSocks5Proxies) > 0 {
		gologger.Print().Msgf("Using upstream SOCKS5 proxies: %s\n", strings.Join(r.options.UpstreamSocks5Proxies, ","))
	}

	if r.options.DNSMapping != "" {
		for _, v := range strings.Split(r.options.DNSMapping, ",") {
			gologger.Print().Msgf("Domain => IP: %s\n", v)
		}

		if r.options.DNSFallbackResolver != "" {
			gologger.Print().Msgf("Fallback Resolver: %s\n", r.options.DNSFallbackResolver)
		}

	}

	return r.proxy.Run()
}

// Close the runner instance
func (r *Runner) Close() {
	r.proxy.Stop()
}
