package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/elazarl/goproxy"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/tinydns"
)

var (
	httpclient *http.Client
	response   *http.Response
	responses  map[string]*http.Response
)

type Options struct {
	DNSListenerAddress       string
	HTTPListenerAddress      string
	HTTPBurpAddress          string
	HTTPProxyListenerAddress string
	OutputFolder             string
}

func main() {
	options := &Options{}
	flag.StringVar(&options.OutputFolder, "output", "db/", "Output Folder")
	flag.StringVar(&options.HTTPListenerAddress, "http-addr", ":80", "HTTP Server Listen Address")
	flag.StringVar(&options.HTTPBurpAddress, "burp-addr", "http://127.0.0.1:8080", "Burp HTTP Address")
	flag.StringVar(&options.DNSListenerAddress, "dns-addr", ":10000", "DNS UDP Server Listen Address")
	flag.StringVar(&options.HTTPProxyListenerAddress, "proxy-addr", ":8081", "HTTP Proxy Server Listen Address")
	flag.Parse()

	dialerOpts := fastdialer.DefaultOptions
	dialerOpts.MaxRetries = 1
	dialerOpts.BaseResolvers = []string{"127.0.0.1" + options.DNSListenerAddress}
	dialer, err := fastdialer.NewDialer(dialerOpts)
	if err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}

	responses = make(map[string]*http.Response)
	httpproxy := goproxy.NewProxyHttpServer()
	httpproxy.Verbose = true
	httpproxy.Tr.DialContext = dialer.Dial
	httpproxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	// httpproxy.OnRequest().DoFunc(OnRequest)
	go func() {
		if err := http.ListenAndServe(options.HTTPProxyListenerAddress, httpproxy); err != nil {
			gologger.Fatal().Msgf("Could not serve proxy: %s\n", err)
		}
	}()

	// dns server
	var domainsToAddresses = map[string]*tinydns.DnsRecord{
		"*": {A: []string{"127.0.0.1"}},
	}
	tinydns, _ := tinydns.New(&tinydns.Options{
		ListenAddress: options.DNSListenerAddress,
		Net:           "udp",
		DnsRecords:    domainsToAddresses,
	})
	go func() {
		if err := tinydns.Run(); err != nil {
			gologger.Fatal().Msgf("Could not serve dns: %s\n", err)
		}
	}()

	// http server
	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		key := req.Header.Get("proxify")
		response := responses[key]
		delete(responses, key)

		for k, v := range response.Header {
			w.Header().Add(k, strings.Join(v, "; "))
		}
		w.WriteHeader(response.StatusCode)
		io.Copy(w, response.Body) //nolint
	})
	go func() {
		if err := http.ListenAndServe(options.HTTPListenerAddress, nil); err != nil {
			gologger.Fatal().Msgf("Could not listen and serve: %s\n", err)
		}
	}()

	// http client proxy
	proxyUrl, err := url.Parse(options.HTTPBurpAddress)
	if err != nil {
		log.Fatal(err)
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		Proxy: http.ProxyURL(proxyUrl),
	}
	httpclient = &http.Client{Transport: transport}

	// process all requests
	root := options.OutputFolder
	err = filepath.Walk(root, visit())
	if err != nil {
		log.Fatal(err)
	}
}

func visit() filepath.WalkFunc {
	return func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		if !strings.HasSuffix(path, ".txt") {
			return nil
		}

		filename := filepath.Base(path)
		filename = strings.TrimSuffix(filename, ".txt")
		filename = strings.TrimSuffix(filename, ".match")

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer func() {
			_ = file.Close()
		}()
		bf := bufio.NewReader(file)

		tokens := strings.Split(filename, "-")
		host := strings.Join(tokens[:len(tokens)-1], "")
		id := strings.Split(tokens[len(tokens)-1], ".")[0]
		log.Println(host, id)

		request, err := http.ReadRequest(bf)
		if err != nil {
			return err
		}
		request.Header.Add("proxify", id)
		response, err = http.ReadResponse(bf, request)
		if err != nil {
			return err
		}

		// We can't have this set. And it only contains "/pkg/net/http/" anyway
		request.RequestURI = ""

		// Since the req.URL will not have all the information set,
		// such as protocol scheme and host, we create a new URL
		u, err := url.Parse("http://" + host)
		if err != nil {
			return err
		}
		request.URL = u

		responses[id] = response
		_, err = httpclient.Do(request)
		return err
	}
}
