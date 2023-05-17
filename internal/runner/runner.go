package runner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Knetic/govaluate"
	"github.com/projectdiscovery/dsl"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils/yaml"
	"github.com/projectdiscovery/proxify"
	"github.com/projectdiscovery/proxify/pkg/certs"
	"github.com/projectdiscovery/proxify/pkg/logger/export"
	"github.com/projectdiscovery/proxify/pkg/logger/file"
	fileutil "github.com/projectdiscovery/utils/file"
)

// Runner contains the internal logic of the program
type Runner struct {
	options      *Options
	proxy        *proxify.Proxy
	exportConfig *export.Config
}

// NewRunner instance
func NewRunner(options *Options) (*Runner, error) {
	if err := certs.LoadCerts(options.Directory); err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}

	if options.OutCAFile != "" {
		err := certs.SaveCAToFile(options.OutCAFile)
		if err != nil {
			return nil, err
		}
		gologger.Print().Msgf("Saved CA File at %v", options.OutCAFile)
		os.Exit(0)
	}

	reader, err := fileutil.SubstituteConfigFromEnvVars(options.ExportConfig)
	if err != nil {
		return nil, err
	}

	exportConfig := &export.Config{}
	err = yaml.DecodeAndValidate(reader, exportConfig)
	if err != nil {
		return nil, err
	}

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
		OutputJsonl:                 options.OutputJsonl,
		UpstreamProxyRequestsNumber: options.UpstreamProxyRequestsNumber,
		Allow:                       options.Allow,
		Deny:                        options.Deny,
		PassThrough:                 options.PassThrough,
		MaxSize:                     exportConfig.MaxSize,
		Elastic:                     exportConfig.Elastic,
		Kafka:                       exportConfig.Kafka,
	})
	if err != nil {
		return nil, err
	}

	fmt.Printf("exportConfig: %+v\n", exportConfig)
	fmt.Printf("exportConfig.Elastic: %+v\n", exportConfig.Elastic)
	fmt.Printf("exportConfig.Kafka: %+v\n", exportConfig.Kafka)
	return &Runner{options: options, proxy: proxy, exportConfig: exportConfig}, nil
}

func (r *Runner) validateExpressions(expressionsGroups ...[]string) error {
	for _, expressionsGroup := range expressionsGroups {
		for _, expression := range expressionsGroup {
			if _, err := govaluate.NewEvaluableExpressionWithFunctions(expression, dsl.DefaultHelperFunctions); err != nil {
				printDslCompileError(err)
				return err
			}
		}
	}
	return nil
}

// Run polling and notification
func (r *Runner) Run() error {

	if err := r.validateExpressions(r.options.RequestDSL, r.options.ResponseDSL, r.options.RequestMatchReplaceDSL, r.options.ResponseMatchReplaceDSL); err != nil {
		return err
	}

	// configuration summary
	if r.options.ListenAddrHTTP != "" {
		gologger.Info().Msgf("HTTP Proxy Listening on %s\n", r.options.ListenAddrHTTP)
	}
	if r.options.ListenAddrSocks5 != "" {
		gologger.Info().Msgf("Socks5 Proxy Listening on %s\n", r.options.ListenAddrSocks5)
	}

	if r.options.OutputDirectory != "" {
		logPath := r.options.OutputDirectory
		if r.options.OutputJsonl {
			logPath = filepath.Join(logPath, file.ProxifyJsonlLogFile)
		}
		gologger.Info().Msgf("Saving proxify traffic to %s\n", logPath)
	}
	if r.exportConfig.Kafka.Addr != "" {
		gologger.Info().Msgf("Sending traffic to Kafka at %s\n", r.exportConfig.Kafka.Addr)
	}
	if r.exportConfig.Elastic.Addr != "" {
		gologger.Info().Msgf("Sending traffic to Elasticsearch at %s\n", r.exportConfig.Elastic.Addr)
	}

	if len(r.options.UpstreamHTTPProxies) > 0 {
		gologger.Info().Msgf("Using upstream HTTP proxies: %s\n", r.options.UpstreamHTTPProxies)
	} else if len(r.options.UpstreamSocks5Proxies) > 0 {
		gologger.Info().Msgf("Using upstream SOCKS5 proxies: %s\n", r.options.UpstreamSocks5Proxies)
	}

	if r.options.DNSMapping != "" {
		for _, v := range strings.Split(r.options.DNSMapping, ",") {
			gologger.Info().Msgf("Domain => IP: %s\n", v)
		}

		if r.options.DNSFallbackResolver != "" {
			gologger.Info().Msgf("Fallback Resolver: %s\n", r.options.DNSFallbackResolver)
		}

	}

	return r.proxy.Run()
}

// Close the runner instance
func (r *Runner) Close() {
	r.proxy.Stop()
}

// printDslCompileError prints the error message for a DSL compilation error
func printDslCompileError(err error) {
	gologger.Error().Msgf("error compiling DSL: %s", err)
	gologger.Info().Msgf("The available custom DSL functions are:")
	gologger.Info().Label("").Msgf(dsl.GetPrintableDslFunctionSignatures(false))
}
