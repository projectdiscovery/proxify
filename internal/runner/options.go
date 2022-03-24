package runner

import (
	"os"
	"path"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/proxify/pkg/logger/elastic"
	"github.com/projectdiscovery/proxify/pkg/logger/kafka"
)

// Options of the runner
type Options struct {
	OutputDirectory             string
	Directory                   string
	CertCacheSize               int
	Verbose                     bool
	Silent                      bool
	Version                     bool
	ListenAddrHTTP              string
	ListenAddrSocks5            string
	ListenDNSAddr               string
	DNSMapping                  string                        // DNSMapping contains user provided hosts
	DNSFallbackResolver         string                        // Listen DNS Ip and port (ip:port)
	NoColor                     bool                          // No Color
	RequestDSL                  string                        // Request Filter DSL
	RequestMatchReplaceDSL      string                        // Request Match-Replace DSL
	ResponseDSL                 string                        // Response Filter DSL
	ResponseMatchReplaceDSL     string                        // Request Match-Replace DSL
	UpstreamHTTPProxies         goflags.NormalizedStringSlice // Upstream HTTP comma separated Proxies (eg http://proxyip:proxyport)
	UpstreamSocks5Proxies       goflags.NormalizedStringSlice // Upstream SOCKS5 comma separated Proxies (eg socks5://proxyip:proxyport)
	UpstreamProxyRequestsNumber int                           // Number of requests before switching upstream proxy
	DumpRequest                 bool                          // Dump requests in separate files
	DumpResponse                bool                          // Dump responses in separate files
	Deny                        string                        // Deny ip/cidr
	Allow                       string                        // Allow ip/cidr
	Elastic                     elastic.Options
	Kafka                       kafka.Options
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

	createGroup(flagSet, "output", "Output",
		// Todo:	flagSet.BoolVar(&options.Dump, "dump", true, "Dump HTTP requests/response to output file"),
		flagSet.StringVarP(&options.OutputDirectory, "output", "o", "logs", "Output Directory to store HTTP proxy logs"),
		flagSet.BoolVar(&options.DumpRequest, "dump-req", false, "Dump only HTTP requests to output file"),
		flagSet.BoolVar(&options.DumpResponse, "dump-resp", false, "Dump only HTTP responses to output file"),
	)

	createGroup(flagSet, "filter", "Filter",
		flagSet.StringVarP(&options.RequestDSL, "request-dsl", "req-fd", "", "Request Filter DSL"),
		flagSet.StringVarP(&options.ResponseDSL, "response-dsl", "resp-fd", "", "Response Filter DSL"),
		flagSet.StringVarP(&options.RequestMatchReplaceDSL, "request-match-replace-dsl", "req-mrd", "", "Request Match-Replace DSL"),
		flagSet.StringVarP(&options.ResponseMatchReplaceDSL, "response-match-replace-dsl", "resp-mrd", "", "Response Match-Replace DSL"),
	)

	createGroup(flagSet, "network", "Network",
		flagSet.StringVarP(&options.ListenAddrHTTP, "http-addr", "ha", "127.0.0.1:8888", "Listening HTTP IP and Port address (ip:port)"),
		flagSet.StringVarP(&options.ListenAddrSocks5, "socks-addr", "sa", "127.0.0.1:10080", "Listening SOCKS IP and Port address (ip:port)"),
		flagSet.StringVarP(&options.ListenDNSAddr, "dns-addr", "da", "", "Listening DNS IP and Port address (ip:port)"),
		flagSet.StringVarP(&options.DNSMapping, "dns-mapping", "dm", "", "Domain to IP DNS mapping (eg domain:ip,domain:ip,..)"),
		flagSet.StringVarP(&options.DNSFallbackResolver, "resolver", "r", "", "Custom DNS resolvers to use (ip:port)"),
	)

	createGroup(flagSet, "proxy", "Proxy",
		flagSet.NormalizedStringSliceVarP(&options.UpstreamHTTPProxies, "http-proxy", "hp", []string{}, "Upstream HTTP Proxies (eg http://proxy-ip:proxy-port)"),
		flagSet.NormalizedStringSliceVarP(&options.UpstreamSocks5Proxies, "socks5-proxy", "sp", []string{}, "Upstream SOCKS5 Proxies (eg socks5://proxy-ip:proxy-port)"),
		flagSet.IntVar(&options.UpstreamProxyRequestsNumber, "c", 1, "Number of requests before switching to the next upstream proxy"),
	)

	createGroup(flagSet, "export", "Export",
		flagSet.StringVar(&options.Elastic.Addr, "elastic-address", "", "elasticsearch address (ip:port)"),
		flagSet.BoolVar(&options.Elastic.SSL, "elastic-ssl", false, "enable elasticsearch ssl"),
		flagSet.BoolVar(&options.Elastic.SSLVerification, "elastic-ssl-verification", false, "enable elasticsearch ssl verification"),
		flagSet.StringVar(&options.Elastic.Username, "elastic-username", "", "elasticsearch username"),
		flagSet.StringVar(&options.Elastic.Password, "elastic-password", "", "elasticsearch password"),
		flagSet.StringVar(&options.Elastic.IndexName, "elastic-index", "proxify", "elasticsearch index name"),
		flagSet.StringVar(&options.Kafka.Addr, "kafka-address", "", "address of kafka broker (ip:port)"),
		flagSet.StringVar(&options.Kafka.Topic, "kafka-topic", "proxify", "kafka topic to publish messages on"),
	)

	createGroup(flagSet, "configuration", "Configuration",
		// Todo: default config file support (homeDir/.config/proxify/config.yaml)
		flagSet.StringVar(&options.Directory, "config", path.Join(homeDir, ".config", "proxify"), "Directory for storing program information"),
		flagSet.IntVar(&options.CertCacheSize, "cert-cache-size", 256, "Number of certificates to cache"),
		flagSet.StringVar(&options.Allow, "allow", "", "Allowed list of IP/CIDR's to be proxied"),
		flagSet.StringVar(&options.Deny, "deny", "", "Denied list of IP/CIDR's to be proxied"),
	)

	createGroup(flagSet, "debug", "debug",
		flagSet.BoolVar(&options.Silent, "silent", false, "Silent"),
		flagSet.BoolVarP(&options.NoColor, "no-color", "nc", true, "No Color"),
		flagSet.BoolVar(&options.Version, "version", false, "Version"),
		flagSet.BoolVarP(&options.Verbose, "verbose", "v", false, "Verbose"),
	)

	_ = flagSet.Parse()
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

func createGroup(flagSet *goflags.FlagSet, groupName, description string, flags ...*goflags.FlagData) {
	flagSet.SetGroup(groupName, description)
	for _, currentFlag := range flags {
		currentFlag.Group(groupName)
	}
}
