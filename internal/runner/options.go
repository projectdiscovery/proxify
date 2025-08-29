package runner

import (
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/proxify/pkg/logger"
	"github.com/projectdiscovery/proxify/pkg/logger/elastic"
	"github.com/projectdiscovery/proxify/pkg/logger/kafka"
	"github.com/projectdiscovery/proxify/pkg/types"
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	permissionutil "github.com/projectdiscovery/utils/permission"
	updateutils "github.com/projectdiscovery/utils/update"
	"gopkg.in/yaml.v2"
)

var (
	cfgFile string
)

// Options of the runner
type Options struct {
	OutputDirectory             string
	OutputFile                  string // for storing the jsonl output
	OutputFormat                string
	LoggerConfig                string
	ConfigDir                   string
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
	OutCAFile                   string
	Deny                        goflags.StringSlice // Deny ip/cidr
	Allow                       goflags.StringSlice // Allow ip/cidr
	Elastic                     elastic.Options
	Kafka                       kafka.Options
	PassThrough                 goflags.StringSlice // Passthrough items list
	MaxSize                     int
	DisableUpdateCheck          bool // DisableUpdateCheck disables automatic update check
	OutputJsonl                 bool // OutputJsonl outputs data in JSONL format
}

func ParseOptions() (*Options, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	options := &Options{}

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`Swiss Army Knife Proxy for rapid deployments. Supports multiple operations such as request/response dump,filtering and manipulation via DSL language, upstream HTTP/Socks5 proxy`)

	flagSet.CreateGroup("output", "Output",
		// Todo:	flagSet.BoolVar(&options.Dump, "dump", true, "Dump HTTP requests/response to output file"),
		flagSet.StringVarP(&options.OutputDirectory, "store-response", "sr", "proxify_logs", "store raw http request / response to output directory"),
		flagSet.StringVarP(&options.OutputFile, "output", "o", "proxify_logs.jsonl", "output file to store proxify logs"),
		flagSet.StringVarP(&options.OutputFormat, "output-format", "of", "jsonl", "output format (jsonl/yaml)"),
		flagSet.BoolVar(&options.DumpRequest, "dump-req", false, "Dump only HTTP requests to output file"),
		flagSet.BoolVar(&options.DumpResponse, "dump-resp", false, "Dump only HTTP responses to output file"),
		flagSet.StringVarP(&options.OutCAFile, "out-ca", "oca", "", "Generate and Save CA File to filename"),
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
	)

	flagSet.CreateGroup("configuration", "Configuration",
		flagSet.StringVar(&cfgFile, "config", "", "path to the proxify configuration file"),
		flagSet.StringVarP(&options.LoggerConfig, "export-config", "ec", filepath.Join(homeDir, ".config", "proxify", logger.LoggerConfigFilename), "proxify export module configuration file"),
		flagSet.StringVar(&options.ConfigDir, "config-directory", filepath.Join(homeDir, ".config", "proxify"), "override the default config path ($home/.config/proxify)"),
		flagSet.IntVar(&options.CertCacheSize, "cert-cache-size", 256, "Number of certificates to cache"),
		flagSet.StringSliceVarP(&options.Allow, "allow", "a", nil, "Allowed list of IP/CIDR's to be proxied", goflags.FileNormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&options.Deny, "deny", "d", nil, "Denied list of IP/CIDR's to be proxied", goflags.FileNormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&options.PassThrough, "passthrough", "pt", nil, "List of passthrough domains", goflags.FileNormalizedStringSliceOptions),
	)

	silent, verbose, veryVerbose := false, false, false
	flagSet.CreateGroup("debug", "debug",
		flagSet.BoolVarP(&options.NoColor, "no-color", "nc", false, "No Color"),
		flagSet.BoolVar(&options.Version, "version", false, "Version"),
		flagSet.BoolVar(&silent, "silent", false, "Silent"),
		flagSet.BoolVarP(&verbose, "verbose", "v", false, "Verbose"),
		flagSet.BoolVarP(&veryVerbose, "very-verbose", "vv", false, "Very Verbose"),
	)

	if err := flagSet.Parse(); err != nil {
		return nil, err
	}

	if options.ConfigDir != "" {
		_ = os.MkdirAll(options.ConfigDir, permissionutil.ConfigFolderPermission)
		readFlagsConfig(flagSet, options.ConfigDir)
	}

	if cfgFile != "" {
		if !fileutil.FileExists(cfgFile) {
			gologger.Fatal().Msgf("given config file '%s' does not exist", cfgFile)
		}
		// merge config file with flags
		if err := flagSet.MergeConfigFile(cfgFile); err != nil {
			gologger.Fatal().Msgf("Could not read config: %s\n", err)
		}
	}

	if err := options.createLoggerConfigIfNotExists(); err != nil {
		return nil, err
	}

	if err := options.parseLoggerConfig(); err != nil {
		return nil, err
	}

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
		latestVersion, err := updateutils.GetToolVersionCallback("proxify", version)()
		if err != nil {
			if verbose {
				gologger.Error().Msgf("proxify version check failed: %v", err.Error())
			}
		} else {
			gologger.Info().Msgf("Current proxify version %v %v", version, updateutils.GetVersionDescription(version, latestVersion))
		}
	}
	options.OutputJsonl = true
	// if OutputFile is not set, set it to default
	if options.OutputFile == "" {
		options.OutputFile = "proxify_logs.jsonl"
	}

	if options.OutputFormat == "yaml" {
		options.OutputFile = strings.ReplaceAll(options.OutputFile, "jsonl", "yaml")
	}

	return options, nil
}

// readFlagsConfig reads the config file from the default config dir and copies it to the current config dir.
func readFlagsConfig(flagset *goflags.FlagSet, configDir string) {
	// check if config.yaml file exists
	defaultCfgFile, err := flagset.GetConfigFilePath()
	if err != nil {
		// something went wrong either dir is not readable or something else went wrong upstream in `goflags`
		// warn and exit in this case
		gologger.Warning().Msgf("Could not read config file: %s\n", err)
		return
	}
	cfgFile := filepath.Join(configDir, "config.yaml")
	if !fileutil.FileExists(cfgFile) {
		if !fileutil.FileExists(defaultCfgFile) {
			// if default config does not exist, warn and exit
			gologger.Warning().Msgf("missing default config file : %s", defaultCfgFile)
			return
		}
		// if does not exist copy it from the default config
		if err = fileutil.CopyFile(defaultCfgFile, cfgFile); err != nil {
			gologger.Warning().Msgf("Could not copy config file: %s\n", err)
		}
		return
	}
	// if config file exists, merge it with the default config
	if err = flagset.MergeConfigFile(cfgFile); err != nil {
		gologger.Warning().Msgf("failed to merge configfile with flags got: %s\n", err)
	}
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

// createLoggerConfigIfNotExists creates export-config if it doesn't exists
func (options *Options) createLoggerConfigIfNotExists() error {
	if fileutil.FileExists(options.LoggerConfig) {
		return nil
	}

	config := &logger.Config{
		Elastic: elastic.Options{},
		Kafka:   kafka.Options{},
	}
	loggerConfigFile, err := os.Create(options.LoggerConfig)
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("could not create config file")
	}
	defer func() {
		_ = loggerConfigFile.Close()
	}()

	err = yaml.NewEncoder(loggerConfigFile).Encode(config)
	return err
}

// parseLoggerConfig parses the logger configuration file
func (options *Options) parseLoggerConfig() error {
	var config logger.Config

	data, err := os.ReadFile(options.LoggerConfig)
	if err != nil {
		return err
	}

	expandedData := os.ExpandEnv(string(data))
	err = yaml.Unmarshal([]byte(expandedData), &config)
	if err != nil {
		return err
	}

	options.Kafka = config.Kafka
	options.Elastic = config.Elastic

	return nil
}
