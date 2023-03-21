package runner

import (
	"math"
	"os"
	"path/filepath"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/proxify/pkg/logger/elastic"
	"github.com/projectdiscovery/proxify/pkg/logger/kafka"
	"github.com/projectdiscovery/proxify/pkg/types"
	updateutils "github.com/projectdiscovery/utils/update"
)

// Options of the runner
type Options struct {
	OutputDirectory             string
	Directory                   string
	CertCacheSize               int
	Verbosity                   types.Verbosity
	Version                     bool
	ListenAddrHTTP              string
	ListenAddrSocks5            string
	ListenDNSAddr               string
	DNSMapping                  string              // DNSMapping contains user provided hosts
	DNSFallbackResolver         string              // Listen DNS Ip and port (ip:port)
	NoColor                     bool                // No Color
	RequestDSL                  goflags.StringSlice // Request Filter DSL
	RequestMatchReplaceDSL      goflags.StringSlice // Request Match-Replace DSL
	ResponseDSL                 goflags.StringSlice // Response Filter DSL
	ResponseMatchReplaceDSL     goflags.StringSlice // Request Match-Replace DSL
	UpstreamHTTPProxies         goflags.StringSlice // Upstream HTTP comma separated Proxies (e.g. http://proxyip:proxyport)
	UpstreamSocks5Proxies       goflags.StringSlice // Upstream SOCKS5 comma separated Proxies (e.g. socks5://proxyip:proxyport)
	UpstreamProxyRequestsNumber int                 // Number of requests before switching upstream proxy
	DumpRequest                 bool                // Dump requests in separate files
	DumpResponse                bool                // Dump responses in separate files
	Deny                        goflags.StringSlice // Deny ip/cidr
	Allow                       goflags.StringSlice // Allow ip/cidr
	Elastic                     elastic.Options
	Kafka                       kafka.Options
	PassThrough                 goflags.StringSlice // Passthrough items list
	MaxSize                     int
	DisableUpdateCheck          bool // DisableUpdateCheck disables automatic update check
}

func ParseOptions() *Options {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		// Almost never here but panic
		panic(err)
	}

	options := &Options{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`Swiss Army Knife Proxy for rapid deployments. Supports multiple operations such as request/response dump,filtering and manipulation via DSL language, upstream HTTP/Socks5 proxy`)

	flagSet.CreateGroup("output", "Output",
		// Todo:	flagSet.BoolVar(&options.Dump, "dump", true, "Dump HTTP requests/response to output file"),
		flagSet.StringVarP(&options.OutputDirectory, "output", "o", "logs", "Output Directory to store HTTP proxy logs"),
		flagSet.BoolVar(&options.DumpRequest, "dump-req", false, "Dump only HTTP requests to output file"),
		flagSet.BoolVar(&options.DumpResponse, "dump-resp", false, "Dump only HTTP responses to output file"),
	)

	flagSet.CreateGroup("update", "Update",
		flagSet.CallbackVarP(GetUpdateCallback(), "update", "up", "update proxify to latest version"),
		flagSet.BoolVarP(&options.DisableUpdateCheck, "disable-update-check", "duc", false, "disable automatic proxify update check"),
	)

	flagSet.CreateGroup("filter", "Filter",
		flagSet.StringSliceVarP(&options.RequestDSL, "request-dsl", "req-fd", nil, "Request Filter DSL", goflags.StringSliceOptions),
		flagSet.StringSliceVarP(&options.ResponseDSL, "response-dsl", "resp-fd", nil, "Response Filter DSL", goflags.StringSliceOptions),
		flagSet.StringSliceVarP(&options.RequestMatchReplaceDSL, "request-match-replace-dsl", "req-mrd", nil, "Request Match-Replace DSL", goflags.StringSliceOptions),
		flagSet.StringSliceVarP(&options.ResponseMatchReplaceDSL, "response-match-replace-dsl", "resp-mrd", nil, "Response Match-Replace DSL", goflags.StringSliceOptions),
	)

	flagSet.CreateGroup("network", "Network",
		flagSet.StringVarP(&options.ListenAddrHTTP, "http-addr", "ha", "127.0.0.1:8888", "Listening HTTP IP and Port address (ip:port)"),
		flagSet.StringVarP(&options.ListenAddrSocks5, "socks-addr", "sa", "127.0.0.1:10080", "Listening SOCKS IP and Port address (ip:port)"),
		flagSet.StringVarP(&options.ListenDNSAddr, "dns-addr", "da", "", "Listening DNS IP and Port address (ip:port)"),
		flagSet.StringVarP(&options.DNSMapping, "dns-mapping", "dm", "", "Domain to IP DNS mapping (eg domain:ip,domain:ip,..)"),
		flagSet.StringVarP(&options.DNSFallbackResolver, "resolver", "r", "", "Custom DNS resolvers to use (ip:port)"),
	)

	flagSet.CreateGroup("proxy", "Proxy",
		flagSet.StringSliceVarP(&options.UpstreamHTTPProxies, "http-proxy", "hp", nil, "Upstream HTTP Proxies (eg http://proxy-ip:proxy-port)", goflags.NormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&options.UpstreamSocks5Proxies, "socks5-proxy", "sp", nil, "Upstream SOCKS5 Proxies (eg socks5://proxy-ip:proxy-port)", goflags.NormalizedStringSliceOptions),
		flagSet.IntVar(&options.UpstreamProxyRequestsNumber, "c", 1, "Number of requests before switching to the next upstream proxy"),
	)

	flagSet.CreateGroup("export", "Export",
		flagSet.IntVar(&options.MaxSize, "max-size", math.MaxInt, "Max export data size (request/responses will be truncated)"),
		flagSet.StringVar(&options.Elastic.Addr, "elastic-address", "", "elasticsearch address (ip:port)"),
		flagSet.BoolVar(&options.Elastic.SSL, "elastic-ssl", false, "enable elasticsearch ssl"),
		flagSet.BoolVar(&options.Elastic.SSLVerification, "elastic-ssl-verification", false, "enable elasticsearch ssl verification"),
		flagSet.StringVar(&options.Elastic.Username, "elastic-username", "", "elasticsearch username"),
		flagSet.StringVar(&options.Elastic.Password, "elastic-password", "", "elasticsearch password"),
		flagSet.StringVar(&options.Elastic.IndexName, "elastic-index", "proxify", "elasticsearch index name"),
		flagSet.StringVar(&options.Kafka.Addr, "kafka-address", "", "address of kafka broker (ip:port)"),
		flagSet.StringVar(&options.Kafka.Topic, "kafka-topic", "proxify", "kafka topic to publish messages on"),
	)

	flagSet.CreateGroup("configuration", "Configuration",
		// Todo: default config file support (homeDir/.config/proxify/config.yaml)
		flagSet.StringVar(&options.Directory, "config", filepath.Join(homeDir, ".config", "proxify"), "Directory for storing program information"),
		flagSet.IntVar(&options.CertCacheSize, "cert-cache-size", 256, "Number of certificates to cache"),
		flagSet.StringSliceVarP(&options.Allow, "allow", "a", nil, "Allowed list of IP/CIDR's to be proxied", goflags.FileNormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&options.Deny, "deny", "d", nil, "Denied list of IP/CIDR's to be proxied", goflags.FileNormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&options.PassThrough, "passthrough", "pt", nil, "List of passthrough domains", goflags.NormalizedStringSliceOptions),
	)

	silent, verbose, veryVerbose := false, false, false
	flagSet.CreateGroup("debug", "debug",
		flagSet.BoolVarP(&options.NoColor, "no-color", "nc", true, "No Color"),
		flagSet.BoolVar(&options.Version, "version", false, "Version"),
		flagSet.BoolVar(&silent, "silent", false, "Silent"),
		flagSet.BoolVarP(&verbose, "verbose", "v", false, "Verbose"),
		flagSet.BoolVarP(&veryVerbose, "very-verbose", "vv", false, "Very Verbose"),
	)

	_ = flagSet.Parse()
	os.MkdirAll(options.Directory, os.ModePerm) //nolint

	// Read the inputs and configure the logging
	options.configureVerbosity(silent, verbose, veryVerbose)
	options.configureOutput()

	if options.Version {
		gologger.Info().Msgf("Current Version: %s\n", version)
		os.Exit(0)
	}

	// Show the user the banner
	showBanner()

	if !options.DisableUpdateCheck {
		latestVersion, err := updateutils.GetVersionCheckCallback("proxify")()
		if err != nil {
			if verbose {
				gologger.Error().Msgf("proxify version check failed: %v", err.Error())
			}
		} else {
			gologger.Info().Msgf("Current proxify version %v %v", version, updateutils.GetVersionDescription(version, latestVersion))
		}
	}

	return options
}

func (options *Options) configureVerbosity(silent, verbose, veryVerbose bool) {
	if silent && (verbose || veryVerbose) {
		gologger.Error().Msgf("The -silent flag and -v/-vv flags cannot be set together\n")
		os.Exit(1)
	}

	if silent {
		options.Verbosity = types.VerbositySilent
	} else if veryVerbose {
		options.Verbosity = types.VerbosityVeryVerbose
	} else if verbose {
		options.Verbosity = types.VerbosityVerbose
	} else {
		options.Verbosity = types.VerbosityDefault
	}
}

func (options *Options) configureOutput() {
	if options.Verbosity <= types.VerbositySilent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	} else if options.Verbosity >= types.VerbosityVerbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}
	if options.NoColor {
		gologger.DefaultLogger.SetFormatter(formatter.NewCLI(true))
	}
}
