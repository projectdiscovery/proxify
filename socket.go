package proxify

import (
	"bytes"
	"crypto/tls"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"
)

// SocketProxy - connect two sockets with TLS inspection
type SocketProxy struct {
	Listener net.Listener
	options  *SocketProxyOptions
}

// SocketConn represent the single full duplex pipe
type SocketConn struct {
	laddr, raddr  net.Addr
	lconn, rconn  net.Conn
	erred         bool
	errsig        chan bool
	httpclient    *http.Client
	HTTPServer    string
	sentBytes     uint64
	receivedBytes uint64
	Verbose       bool
	OutputHex     bool
	Timeout       time.Duration
}

type SocketProxyOptions struct {
	Protocol        string
	ListenAddress   string
	RemoteAddress   string
	HTTPProxy       string
	HTTPServer      string
	listenAddress   net.TCPAddr
	remoteAddress   net.TCPAddr
	TLSClientConfig *tls.Config
	TLSClient       bool
	TLSServerConfig *tls.Config
	TLSServer       bool
	Verbose         bool
	OutputHex       bool
	Timeout         time.Duration
}

func (so *SocketProxyOptions) Clone() SocketProxyOptions {
	return SocketProxyOptions{
		Protocol:        so.Protocol,
		ListenAddress:   so.ListenAddress,
		RemoteAddress:   so.RemoteAddress,
		HTTPProxy:       so.HTTPProxy,
		HTTPServer:      so.HTTPServer,
		listenAddress:   so.listenAddress,
		remoteAddress:   so.remoteAddress,
		TLSClientConfig: so.TLSClientConfig,
		TLSClient:       so.TLSClient,
		TLSServerConfig: so.TLSServerConfig,
		TLSServer:       so.TLSServer,
	}
}

func NewSocketProxy(options *SocketProxyOptions) *SocketProxy {
	return &SocketProxy{options: options}
}

func (p *SocketProxy) Run() error {
	var (
		listener net.Listener
		err      error
	)
	if p.options.TLSServer {
		config := &tls.Config{InsecureSkipVerify: true}
		if p.options.TLSServerConfig != nil {
			config = p.options.TLSServerConfig
		}
		listener, err = tls.Listen(p.options.Protocol, p.options.ListenAddress, config)
	} else {
		listener, err = net.Listen(p.options.Protocol, p.options.ListenAddress)
	}
	if err != nil {
		return err
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err)
			return err
		}
		go p.Proxy(conn)
	}
}

func (p *SocketProxy) Proxy(conn net.Conn) error {
	var (
		socketConn SocketConn
		err        error
	)

	socketConn.Timeout = p.options.Timeout
	socketConn.Verbose = p.options.Verbose
	socketConn.OutputHex = p.options.OutputHex

	socketConn.lconn = conn
	defer socketConn.lconn.Close()

	if p.options.TLSClient {
		config := &tls.Config{
			InsecureSkipVerify: true,
		}
		if p.options.TLSClientConfig != nil {
			config = p.options.TLSClientConfig
		}
		socketConn.rconn, err = tls.Dial("tcp", p.options.RemoteAddress, config)
	} else {
		socketConn.rconn, err = net.Dial("tcp", p.options.RemoteAddress)
	}
	if err != nil {
		log.Println(err)
		return nil
	}

	defer socketConn.rconn.Close()

	if p.options.HTTPProxy != "" {
		proxyURL, err := url.Parse(p.options.HTTPProxy)
		if err != nil {
			return nil
		}
		socketConn.httpclient = &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
			},
		}
		socketConn.HTTPServer = p.options.HTTPServer
	}
	socketConn.errsig = make(chan bool)
	socketConn.fullduplex()

	return nil
}

func (p *SocketConn) err(s string, err error) {
	log.Println(err)
	if p.erred {
		return
	}
	if err != io.EOF {
		log.Printf(s, err)
	}
	p.errsig <- true
	p.erred = true
}

func (p *SocketConn) fullduplex() {
	//bidirectional copy
	log.Printf("Opened %s >>> %s", p.lconn.LocalAddr(), p.rconn.RemoteAddr())
	go p.pipe(p.lconn, p.rconn)
	go p.pipe(p.rconn, p.lconn)
	if p.Timeout > 0 {
		p.lconn.SetDeadline(time.Now().Add(p.Timeout))
		p.rconn.SetDeadline(time.Now().Add(p.Timeout))
	}

	//wait for close...
	<-p.errsig
	log.Printf("Closed (%d bytes sent, %d bytes received)", p.sentBytes, p.receivedBytes)
}

func (p *SocketConn) pipe(src, dst io.ReadWriter) {
	islocal := src == p.lconn

	var dataDirection string
	if islocal {
		dataDirection = ">>> %d bytes sent%s"
	} else {
		dataDirection = "<<< %d bytes received%s"
	}

	byteFormat := "%s"
	if p.OutputHex {
		byteFormat = "%x"
	}
	//directional copy (64k buffer)
	buff := make([]byte, 0xffff)
	for {
		n, err := src.Read(buff)
		if err != nil {
			p.err("Read failed: %s\n", err)
			return
		}
		b := buff[:n]

		// show output
		log.Printf(dataDirection, n, "")
		log.Printf(byteFormat, b)

		// something custom
		if bytes.HasPrefix(b, []byte{0x16, 0x03}) {
			print("[!] SSL/TLS handshake detected, provide a server cert and key to enable interception.")
		}

		if p.httpclient != nil {
			resp, err := p.httpclient.Post(p.HTTPServer, "", bytes.NewReader(b))
			if err != nil {
				log.Println(err)
			} else {
				b, _ = ioutil.ReadAll(resp.Body)
				resp.Body.Close()
			}
		}

		// write out result
		n, err = dst.Write(b)
		if err != nil {
			p.err("Write failed: %s\n", err)
			return
		}

		if islocal {
			p.sentBytes += uint64(n)
		} else {
			p.receivedBytes += uint64(n)
		}
	}
}
