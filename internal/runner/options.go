package runner

import (
	"os"
	"path"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/proxify/pkg/types"
)

// Options of the runner
type Options struct {
	OutputDirectory         string // Output Folder
	Directory               string // Directory for storing program information
	CertCacheSize           int    // Number of certificates to cache
	Verbose                 bool   // Verbose mode
	Silent                  bool   // Silent mode
	Version                 bool   // Version of the program
	ListenAddr              string // Listen Ip and port (ip:port)
	ListenDNSAddr           string
	DNSMapping              string           // DNSMapping contains user provided hosts
	DNSFallbackResolver     string           // Listen DNS Ip and port (ip:port)
	NoColor                 bool             // No Color
	RequestDSL              string           // Request Filter DSL
	RequestMatchReplaceDSL  string           // Request Match-Replace DSL
	ResponseDSL             string           // Response Filter DSL
	ResponseMatchReplaceDSL string           // Request Match-Replace DSL
	UpstreamHTTPProxy       string           // Upstream HTTP Proxy (eg http://proxyip:proxyport)
	UpstreamSocks5Proxy     string           // Upstream SOCKS5 Proxy (eg socks5://proxyip:proxyport)
	DumpRequest             bool             // Dump requests in separate files
	DumpResponse            bool             // Dump responses in separate files
	Deny                    types.CustomList // Deny ip/cidr
	Allow                   types.CustomList // Allow ip/cidr
}

func ParseOptions() *Options {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		// Almost never here but panic
		panic(err)
	}

	options := &Options{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`Swiss Army Knife Proxy for rapid deployments. Supports multiple operations such as request/response dump, filtering and manipulation via DSL language, upstream HTTP/Socks5 proxy`)

	createGroup(flagSet, "output", "Output",
		flagSet.StringVar(&options.OutputDirectory, "output", "logs", "Output Folder"),
		flagSet.BoolVar(&options.Verbose, "v", false, "Verbose"),
		flagSet.StringVar(&options.Directory, "config", path.Join(homeDir, ".config", "proxify"), "Directory for storing program information"),
		flagSet.IntVar(&options.CertCacheSize, "cert-cache-size", 256, "Number of certificates to cache"),
		flagSet.BoolVar(&options.DumpRequest, "dump-req", false, "Dump requests in separate files"),
		flagSet.BoolVar(&options.DumpResponse, "dump-resp", false, "Dump responses in separate files"),
		flagSet.BoolVar(&options.Silent, "silent", false, "Silent"),
		flagSet.BoolVar(&options.NoColor, "no-color", true, "No Color"),
		flagSet.BoolVar(&options.Version, "version", false, "Version"),
	)

	createGroup(flagSet, "filter", "Filter",
		flagSet.Var(&options.Allow, "allow", "Whitelist ip/cidr"),
		flagSet.Var(&options.Deny, "deny", "Blacklist ip/cidr"),
		flagSet.StringVar(&options.RequestDSL, "request-dsl", "", "Request Filter DSL"),
		flagSet.StringVar(&options.ResponseDSL, "response-dsl", "", "Response Filter DSL"),
		flagSet.StringVar(&options.RequestMatchReplaceDSL, "request-match-replace-dsl", "", "Request Match-Replace DSL"),
		flagSet.StringVar(&options.ResponseMatchReplaceDSL, "response-match-replace-dsl", "", "Request Match-Replace DSL"),
	)

	createGroup(flagSet, "network", "Network",
		flagSet.StringVar(&options.ListenAddr, "addr", "127.0.0.1:8888", "Listen Ip and port (ip:port)"),
		flagSet.StringVar(&options.DNSFallbackResolver, "dns-resolver", "", "Listen DNS Ip and port (ip:port)"),
		flagSet.StringVar(&options.ListenDNSAddr, "dns-addr", "", "Listen DNS Ip and port (ip:port)"),
		flagSet.StringVar(&options.DNSMapping, "dns-mapping", "", "DNS A mapping (eg domain:ip,domain:ip,..)"),
		flagSet.StringVar(&options.UpstreamHTTPProxy, "http-proxy", "", "Upstream HTTP Proxy (eg http://proxyip:proxyport"),
		flagSet.StringVar(&options.UpstreamSocks5Proxy, "socks5-proxy", "", "Upstream SOCKS5 Proxy (eg socks5://proxyip:proxyport)"),
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
