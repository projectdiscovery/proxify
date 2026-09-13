package proxify

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/martian/v3"
	"github.com/projectdiscovery/proxify/pkg/logger"
	"github.com/projectdiscovery/proxify/pkg/logger/elastic"
	"github.com/projectdiscovery/proxify/pkg/logger/kafka"
	"github.com/projectdiscovery/proxify/pkg/types"
)

func TestProxyForwardsPOSTBody(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		name := "content-length"
		if chunked {
			name = "chunked"
		}
		t.Run(name, func(t *testing.T) {
			payload := strings.Repeat("POST payload\x00\r\n", 8192)
			prefixReceived := make(chan struct{}, 1)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				prefix := make([]byte, 1024)
				if _, err := io.ReadFull(r.Body, prefix); err != nil {
					t.Errorf("read upstream prefix: %v", err)
				}
				if chunked {
					prefixReceived <- struct{}{}
				}
				rest, err := io.ReadAll(r.Body)
				body := append(prefix, rest...)
				if err != nil {
					t.Errorf("read upstream body: %v", err)
				}
				if string(body) != payload {
					t.Errorf("upstream body differs: got %d bytes, want %d", len(body), len(payload))
				}
				if chunked {
					if len(r.TransferEncoding) != 1 || r.TransferEncoding[0] != "chunked" {
						t.Errorf("TransferEncoding = %v", r.TransferEncoding)
					}
				} else if r.ContentLength != int64(len(payload)) {
					t.Errorf("ContentLength = %d, want %d", r.ContentLength, len(payload))
				}
				_, _ = w.Write([]byte("complete response"))
			}))
			defer upstream.Close()
			l := logger.NewLogger(&logger.OptionsLogger{Elastic: &elastic.Options{}, Kafka: &kafka.Options{}, Verbosity: types.VerbositySilent})
			defer l.Close()
			p := &Proxy{options: &Options{}, logger: l}
			hp := martian.NewProxy()
			transport := &http.Transport{}
			defer transport.CloseIdleConnections()
			hp.SetRoundTripper(transport)
			hp.SetRequestModifier(p)
			hp.SetResponseModifier(p)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() { defer close(done); _ = hp.Serve(listener) }()
			defer func() { listener.Close(); hp.Close(); <-done }()
			proxyURL, err := url.Parse("http://" + listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			clientTransport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
			defer clientTransport.CloseIdleConnections()
			client := &http.Client{Transport: clientTransport, Timeout: 5 * time.Second}
			for i := 0; i < 3; i++ {
				req, err := http.NewRequest(http.MethodPost, upstream.URL, strings.NewReader(payload))
				if err != nil {
					t.Fatal(err)
				}
				var writeDone chan error
				if chunked {
					reader, writer := io.Pipe()
					req.Body = reader
					req.GetBody = nil
					req.ContentLength = -1
					writeDone = make(chan error, 1)
					go func() {
						_, err := io.WriteString(writer, payload[:1024])
						if err == nil {
							// The proxy must forward the prefix before the upload finishes.
							select {
							case <-prefixReceived:
								_, err = io.WriteString(writer, payload[1024:])
							case <-time.After(3 * time.Second):
								err = fmt.Errorf("upstream did not receive prefix before EOF")
							}
						}
						_ = writer.CloseWithError(err)
						writeDone <- err
					}()
				}
				resp, err := client.Do(req)
				if writeDone != nil {
					if writeErr := <-writeDone; writeErr != nil {
						t.Error(writeErr)
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if string(body) != "complete response" {
					t.Fatalf("response body = %q", body)
				}
			}
		})
	}
}

func TestMatchReplaceRequestUpdatesFraming(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://example.test/", strings.NewReader("old"))
	req.Header.Set("Content-Length", "3")
	p := &Proxy{options: &Options{RequestMatchReplaceDSL: []string{`replace(replace(request, 'old', 'longer'), 'Content-Length: 3', 'Content-Length: 6')`}}}
	if err := p.MatchReplaceRequest(req); err != nil {
		t.Fatal(err)
	}
	if req.ContentLength != 6 {
		t.Fatalf("ContentLength = %d, want 6", req.ContentLength)
	}
	body, err := io.ReadAll(req.Body)
	req.Body.Close()
	if err != nil || string(body) != "longer" {
		t.Fatalf("body = %q, %v", body, err)
	}
}
