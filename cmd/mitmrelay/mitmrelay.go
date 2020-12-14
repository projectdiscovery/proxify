package main

import (
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/proxify"
	"github.com/projectdiscovery/tinydns"
)

type Options struct {
	DNSListenerAddress  string
	HTTPListenerAddress string
	HTTPProxy           string
	OutputFolder        string
	ServerTLS           bool
	ServerCert          string
	ServerKey           string
	ClientTLS           bool
	ClientCert          string
	ClientKey           string
	Protocol            string
	Relays              Relays
	DNSFallbackResolver string
	ListenDNSAddr       string
	DNSMapping          string
	Timeout             int
}

func httpserver(addr string) error {
	// echo server
	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		io.Copy(w, req.Body)
	})

	return http.ListenAndServe(addr, nil)
}

func dnsserver(listenAddr, resolverAddr, dnsMap string) {
	domainsToAddresses := make(map[string]string)
	for _, dnsitem := range strings.Split(dnsMap, ",") {
		tokens := strings.Split(dnsitem, ":")
		if len(tokens) != 2 {
			continue
		}
		domainsToAddresses[tokens[0]] = tokens[1]
	}
	tinydns := tinydns.NewTinyDNS(&tinydns.OptionsTinyDNS{
		ListenAddress:       listenAddr,
		FallbackDNSResolver: resolverAddr,
		Net:                 "udp",
		DomainToAddress:     domainsToAddresses,
	})
	tinydns.Run()
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
			log.Fatal(err)
		}
		config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
		proxyOpts.TLSClientConfig = &config
	}

	// TLS Client => Relay
	proxyOpts.TLSServer = options.ServerTLS
	if options.ServerCert != "" && options.ServerKey != "" {
		cert, err := tls.LoadX509KeyPair(options.ServerCert, options.ServerKey)
		if err != nil {
			log.Fatal(err)
		}
		config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
		proxyOpts.TLSServerConfig = &config
	}
	proxyOpts.Protocol = options.Protocol
	proxyOpts.HTTPProxy = options.HTTPProxy

	if options.Timeout >= 0 {
		proxyOpts.Timeout = time.Duration(options.Timeout) * time.Second
	}

	go httpserver(options.HTTPListenerAddress)
	go dnsserver(options.ListenDNSAddr, options.DNSFallbackResolver, options.DNSMapping)

	var wgproxies sync.WaitGroup

	for _, relay := range options.Relays {
		wgproxies.Add(1)
		go func(relay string) {
			defer wgproxies.Done()
			addresses := strings.Split(relay, "=>")
			if len(addresses) != 2 {
				log.Printf("[!] Skipping invalid relay %s", relay)
				return
			}
			ropts := proxyOpts.Clone()
			ropts.ListenAddress, ropts.RemoteAddress = strings.TrimSpace(addresses[0]), strings.TrimSpace(addresses[1])
			sproxy := proxify.NewSocketProxy(&ropts)
			log.Printf("[+] Relay listening on %s -> %s", ropts.ListenAddress, ropts.RemoteAddress)
			log.Print(sproxy.Run())
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
