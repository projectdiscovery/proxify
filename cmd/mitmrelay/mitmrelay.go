package main

import (
	"crypto/tls"
	"flag"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/proxify"
	"github.com/projectdiscovery/tinydns"
)

type Options struct {
	DNSListenerAddress      string
	HTTPListenerAddress     string
	HTTPProxy               string
	OutputFolder            string
	ServerTLS               bool
	ServerCert              string
	ServerKey               string
	ClientTLS               bool
	ClientCert              string
	ClientKey               string
	Protocol                string
	Relays                  Relays
	DNSFallbackResolver     string
	ListenDNSAddr           string
	DNSMapping              string
	Timeout                 int
	RequestMatchReplaceDSL  string
	ResponseMatchReplaceDSL string
}

func httpserver(addr string) error {
	// echo server
	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		io.Copy(w, req.Body) //nolint
	})

	return http.ListenAndServe(addr, nil)
}

func dnsserver(listenAddr, resolverAddr, dnsMap string) {
	domainsToAddresses := make(map[string]*tinydns.DnsRecord)
	for _, dnsitem := range strings.Split(dnsMap, ",") {
		tokens := strings.Split(dnsitem, ":")
		if len(tokens) != 2 {
			continue
		}
		domainsToAddresses[tokens[0]] = &tinydns.DnsRecord{A: []string{tokens[1]}}
	}
	tinydns, _ := tinydns.New(&tinydns.Options{
		ListenAddress:   listenAddr,
		UpstreamServers: []string{resolverAddr},
		Net:             "udp",
		DnsRecords:      domainsToAddresses,
	})
	go func() {
		if err := tinydns.Run(); err != nil {
			gologger.Fatal().Msgf("%s\n", err)
		}
	}()
}

func main() {
	options := &Options{}
	flag.StringVar(&options.OutputFolder, "output", "logs/", "Output Folder")
	flag.StringVar(&options.HTTPListenerAddress, "http-addr", "127.0.0.1:49999", "HTTP Server Listen Address")
	flag.StringVar(&options.HTTPProxy, "proxy-addr", "", "HTTP Proxy Address")
	flag.BoolVar(&options.ServerTLS, "tls-server", false, "Client => Relay should use tls")
	flag.StringVar(&options.ServerCert, "server-cert", "", "Client => Relay Cert File")
	flag.StringVar(&options.ServerKey, "server-key", "", "Client => Relay Key File")
	flag.BoolVar(&options.ClientTLS, "tls-client", false, "Relay => Server should use tls")
	flag.StringVar(&options.ClientCert, "client-cert", "", "Relay => Server Cert File")
	flag.StringVar(&options.ClientKey, "client-key", "", "Relay => Server Key File")
	flag.StringVar(&options.DNSFallbackResolver, "resolver-addr", "", "Listen DNS Ip and port (ip:port)")
	flag.StringVar(&options.ListenDNSAddr, "dns-addr", ":5353", "Listen DNS Ip and port (ip:port)")
	flag.StringVar(&options.DNSMapping, "dns-mapping", "", "DNS A mapping (eg domain:ip,domain:ip,..)")
	flag.IntVar(&options.Timeout, "timeout", 180, "Connection Timeout In Seconds")
	flag.StringVar(&options.RequestMatchReplaceDSL, "request-match-replace-dsl", "", "Request Match-Replace DSL")
	flag.StringVar(&options.ResponseMatchReplaceDSL, "response-match-replace-dsl", "", "Request Match-Replace DSL")
	// Single protocol for now
	flag.StringVar(&options.Protocol, "protocol", "tcp", "tcp or udp")
	flag.Var(&options.Relays, "relay", "listen_ip:listen_port => destination_ip:destination_port")
	flag.Parse()

	var proxyOpts proxify.SocketProxyOptions

	// TLS Relay => Server
	proxyOpts.TLSClient = options.ClientTLS
	if options.ClientCert != "" && options.ClientKey != "" {
		cert, err := tls.LoadX509KeyPair(options.ClientCert, options.ClientKey)
		if err != nil {
			gologger.Fatal().Msgf("%s\n", err)
		}
		config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
		proxyOpts.TLSClientConfig = &config
	}

	// TLS Client => Relay
	proxyOpts.TLSServer = options.ServerTLS
	if options.ServerCert != "" && options.ServerKey != "" {
		cert, err := tls.LoadX509KeyPair(options.ServerCert, options.ServerKey)
		if err != nil {
			gologger.Fatal().Msgf("%s\n", err)
		}
		config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
		proxyOpts.TLSServerConfig = &config
	}
	proxyOpts.Protocol = options.Protocol
	proxyOpts.HTTPProxy = options.HTTPProxy
	proxyOpts.RequestMatchReplaceDSL = []string{options.RequestMatchReplaceDSL}
	proxyOpts.ResponseMatchReplaceDSL = []string{options.ResponseMatchReplaceDSL}

	if options.Timeout >= 0 {
		proxyOpts.Timeout = time.Duration(options.Timeout) * time.Second
	}

	go httpserver(options.HTTPListenerAddress)                                           //nolint
	go dnsserver(options.ListenDNSAddr, options.DNSFallbackResolver, options.DNSMapping) //nolint

	var wgproxies sync.WaitGroup

	for _, relay := range options.Relays {
		wgproxies.Add(1)
		go func(relay string) {
			defer wgproxies.Done()
			addresses := strings.Split(relay, "=>")
			if len(addresses) != 2 {
				gologger.Print().Msgf("[!] Skipping invalid relay %s", relay)
				return
			}
			ropts := proxyOpts.Clone()
			ropts.ListenAddress, ropts.RemoteAddress = strings.TrimSpace(addresses[0]), strings.TrimSpace(addresses[1])
			sproxy := proxify.NewSocketProxy(&ropts)
			gologger.Print().Msgf("[+] Relay listening on %s -> %s", ropts.ListenAddress, ropts.RemoteAddress)
			gologger.Print().Msgf("%s\n", sproxy.Run())
		}(relay)
	}

	wgproxies.Wait()
}

type Relays []string

func (r *Relays) String() string {
	return ""
}

func (r *Relays) Set(value string) error {
	*r = append(*r, value)
	return nil
}
