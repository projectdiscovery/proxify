package runner

import (
	"flag"
	"os"
	"path"

	"github.com/projectdiscovery/gologger"
)

// Options of the internal runner
//nolint:maligned // used once
type Options struct {
	OutputDirectory         string
	Directory               string
	CertCacheSize           int
	Verbose                 bool
	Silent                  bool
	Version                 bool
	ListenAddr              string
	ListenDNSAddr           string
	DNSMapping              string
	DNSFallbackResolver     string
	NoColor                 bool
	RequestDSL              string
	RequestMatchReplaceDSL  string
	ResponseDSL             string
	ResponseMatchReplaceDSL string
	UpstreamHTTPProxy       string
	UpstreamSocks5Proxy     string
}

func ParseOptions() *Options {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		// Almost never here but panic
		panic(err)
	}

	options := &Options{}
	flag.StringVar(&options.OutputDirectory, "output", "logs", "Output Folder")
	flag.BoolVar(&options.Verbose, "v", false, "Verbose")
	flag.StringVar(&options.Directory, "config", path.Join(homeDir, ".config", "proxify"), "Directory for storing program information")
	flag.IntVar(&options.CertCacheSize, "cert-cache-size", 256, "Number of certificates to cache")
	flag.BoolVar(&options.Silent, "silent", false, "Silent")
	flag.BoolVar(&options.NoColor, "no-color", true, "No Color")
	flag.BoolVar(&options.Version, "version", false, "Version")
	flag.StringVar(&options.RequestDSL, "request-dsl", "", "Request Filter DSL")
	flag.StringVar(&options.ResponseDSL, "response-dsl", "", "Response Filter DSL")
	flag.StringVar(&options.RequestMatchReplaceDSL, "request-match-replace-dsl", "", "Request Match-Replace DSL")
	flag.StringVar(&options.ResponseMatchReplaceDSL, "response-match-replace-dsl", "", "Request Match-Replace DSL")
	flag.StringVar(&options.ListenAddr, "addr", "127.0.0.1:8080", "Listen Ip and port (ip:port)")
	flag.StringVar(&options.DNSFallbackResolver, "dns-resolver", "", "Listen DNS Ip and port (ip:port)")
	flag.StringVar(&options.ListenDNSAddr, "dns-addr", "", "Listen DNS Ip and port (ip:port)")
	flag.StringVar(&options.DNSMapping, "dns-mapping", "", "DNS A mapping (eg domain:ip,domain:ip,..)")
	flag.StringVar(&options.UpstreamHTTPProxy, "http-proxy", "", "Upstream HTTP Proxy (eg http://proxyip:proxyport")
	flag.StringVar(&options.UpstreamSocks5Proxy, "socks5-proxy", "", "Upstream SOCKS5 Proxy (eg socks5://proxyip:proxyport")

	flag.Parse()
	_ = os.MkdirAll(options.Directory, os.ModePerm)

	// Read the inputs and configure the logging
	options.configureOutput()

	if options.Version {
		gologger.Infof("Current Version: %s\n", Version)
		os.Exit(0)
	}

	// Show the user the banner
	showBanner()

	return options
}

func (options *Options) configureOutput() {
	if options.Verbose {
		gologger.MaxLevel = gologger.Verbose
	}
	if options.NoColor {
		gologger.UseColors = false
	}
	if options.Silent {
		gologger.MaxLevel = gologger.Silent
	}
}
