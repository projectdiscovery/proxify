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
		Silent:                  options.Silent,
		Directory:               options.Directory,
		CertCacheSize:           options.CertCacheSize,
		Verbose:                 options.Verbose,
		ListenAddr:              options.ListenAddr,
		OutputDirectory:         options.OutputDirectory,
		RequestDSL:              options.RequestDSL,
		ResponseDSL:             options.ResponseDSL,
		UpstreamHTTPProxy:       options.UpstreamHTTPProxy,
		UpstreamSock5Proxy:      options.UpstreamSocks5Proxy,
		ListenDNSAddr:           options.ListenDNSAddr,
		DNSMapping:              options.DNSMapping,
		DNSFallbackResolver:     options.DNSFallbackResolver,
		RequestMatchReplaceDSL:  options.RequestMatchReplaceDSL,
		ResponseMatchReplaceDSL: options.ResponseMatchReplaceDSL,
	})
	if err != nil {
		return nil, err
	}
	return &Runner{options: options, proxy: proxy}, nil
}

// Run polling and notification
func (r *Runner) Run() error {
	// configuration summary
	gologger.Printf("Proxy Listening on %s\n", r.options.ListenAddr)
	if r.options.OutputDirectory != "" {
		gologger.Printf("Saving traffic to %s\n", r.options.OutputDirectory)
	}

	if r.options.UpstreamHTTPProxy != "" {
		gologger.Printf("Using upstream HTTP proxy: %s\n", r.options.UpstreamHTTPProxy)
	} else if r.options.UpstreamSocks5Proxy != "" {
		gologger.Printf("Using upstream SOCKS5 proxy: %s\n", r.options.UpstreamSocks5Proxy)
	}

	if r.options.DNSMapping != "" {
		for _, v := range strings.Split(r.options.DNSMapping, ",") {
			gologger.Printf("Domain => IP: %s\n", v)
		}

		if r.options.DNSFallbackResolver != "" {
			gologger.Printf("Fallback Resolver: %s\n", r.options.DNSFallbackResolver)
		}

	}

	return r.proxy.Run()
}

// Close the runner instance
func (r *Runner) Close() {
	r.proxy.Stop()
}
