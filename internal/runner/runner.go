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
		Directory:                   options.Directory,
		CertCacheSize:               options.CertCacheSize,
		Verbosity:                   options.Verbosity,
		ListenAddrHTTP:              options.ListenAddrHTTP,
		ListenAddrSocks5:            options.ListenAddrSocks5,
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
		Elastic:                     &options.Elastic,
		Kafka:                       &options.Kafka,
		Allow:                       options.Allow,
		Deny:                        options.Deny,
	})
	if err != nil {
		return nil, err
	}
	return &Runner{options: options, proxy: proxy}, nil
}

// Run polling and notification
func (r *Runner) Run() error {
	// configuration summary
	if r.options.ListenAddrHTTP != "" {
		gologger.Print().Msgf("HTTP Proxy Listening on %s\n", r.options.ListenAddrHTTP)
	}
	if r.options.ListenAddrSocks5 != "" {
		gologger.Print().Msgf("Socks5 Proxy Listening on %s\n", r.options.ListenAddrSocks5)
	}

	if r.options.OutputDirectory != "" {
		gologger.Print().Msgf("Saving traffic to %s\n", r.options.OutputDirectory)
	}
	if r.options.Kafka.Addr != "" {
		gologger.Print().Msgf("Sending traffic to Kafka at %s\n", r.options.Kafka.Addr)
	}
	if r.options.Elastic.Addr != "" {
		gologger.Print().Msgf("Sending traffic to Elasticsearch at %s\n", r.options.Elastic.Addr)
	}

	if len(r.options.UpstreamHTTPProxies) > 0 {
		gologger.Print().Msgf("Using upstream HTTP proxies: %s\n", r.options.UpstreamHTTPProxies)
	} else if len(r.options.UpstreamSocks5Proxies) > 0 {
		gologger.Print().Msgf("Using upstream SOCKS5 proxies: %s\n", r.options.UpstreamSocks5Proxies)
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
