package runner

import (
	"flag"
	"os"
	"path"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/proxify/pkg/types"
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
	DumpRequest             bool
	DumpResponse            bool
	Deny                    types.CustomList
	Allow                   types.CustomList
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
	flag.StringVar(&options.UpstreamSocks5Proxy, "socks5-proxy", "", "Upstream SOCKS5 Proxy (eg socks5://proxyip:proxyport)")
	flag.BoolVar(&options.DumpRequest, "dump-req", false, "Dump requests in separate files")
	flag.BoolVar(&options.DumpResponse, "dump-resp", false, "Dump responses in separate files")
	flag.Var(&options.Allow, "allow", "Whitelist ip/cidr")
	flag.Var(&options.Deny, "deny", "Blacklist ip/cidr")

	flag.Parse()
	os.MkdirAll(options.Directory, os.ModePerm) //nolint

	// Read the inputs and configure the logging
	options.configureOutput()

	if options.Version {
		gologger.Info().Msgf("Current Version: %s\n", Version)
		os.Exit(0)
	}

	// Show the user the banner
	showBanner()

	return options
}

func (options *Options) configureOutput() {
	if options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}
	if options.NoColor {
		gologger.DefaultLogger.SetFormatter(formatter.NewCLI(true))
	}
	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}
}
