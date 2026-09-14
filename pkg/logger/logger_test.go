package logger

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/martian/v3"
	"github.com/projectdiscovery/proxify/pkg/logger/har"
	"github.com/projectdiscovery/proxify/pkg/types"
)

func closeErr(t *testing.T, c io.Closer) {
	t.Helper()
	if err := c.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestLogRequestPreservesForwardedBody(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		t.Run(fmt.Sprintf("chunked=%t", chunked), func(t *testing.T) {
			const body = "original POST body"
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read upstream body: %v", err)
				}
				if string(got) != body {
					t.Errorf("upstream body = %q, want %q", got, body)
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer upstream.Close()
			framing := fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(body), body)
			if chunked {
				framing = fmt.Sprintf("Transfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", len(body), body)
			}
			req, err := http.ReadRequest(bufio.NewReader(strings.NewReader("POST " + upstream.URL + "/ HTTP/1.1\r\nHost: example.test\r\n" + framing)))
			if err != nil {
				t.Fatal(err)
			}
			defer closeErr(t, req.Body)
			l := &Logger{options: &OptionsLogger{Verbosity: types.VerbosityVeryVerbose}, asyncqueue: make(chan logTransaction, 1)}
			if err := l.LogRequest(req, types.UserData{}); err != nil {
				t.Fatal(err)
			}
			// Logging runs concurrently with forwarding, using captured bytes only.
			close(l.asyncqueue)
			done := make(chan struct{})
			go func() { defer close(done); l.AsyncWrite() }()
			defer func() { closeErr(t, req.Body); <-done }()
			req.RequestURI = ""
			client := &http.Client{Timeout: 3 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			closeErr(t, resp.Body)
		})
	}
}

func TestLogResponseUsesCapturedRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://example.test/", strings.NewReader("request payload"))
	l := &Logger{options: &OptionsLogger{}, asyncqueue: make(chan logTransaction, 2)}
	if err := l.LogRequest(req, types.UserData{}); err != nil {
		t.Fatal(err)
	}
	requestLog := <-l.asyncqueue
	// The transport may consume and close the request before response logging starts.
	if _, err := io.Copy(io.Discard, req.Body); err != nil {
		t.Fatal(err)
	}
	closeErr(t, req.Body)
	resp := &http.Response{Request: req, Body: io.NopCloser(strings.NewReader("response payload")), Header: make(http.Header)}
	if err := l.LogResponse(resp, types.UserData{}); err != nil {
		t.Fatal(err)
	}
	responseLog := <-l.asyncqueue
	for name, capture := range map[string]*bodyCapture{"request log": requestLog.requestBody, "response log request": responseLog.requestBody} {
		body, _, err := capture.snapshot()
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(body)
		if err != nil || string(got) != "request payload" {
			t.Errorf("%s = %q, %v", name, got, err)
		}
	}
	got, err := io.ReadAll(resp.Body)
	if err != nil || string(got) != "response payload" {
		t.Fatalf("live response = %q, %v", got, err)
	}
	closeErr(t, resp.Body)
	loggedBody, _, err := responseLog.responseBody.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	got, err = io.ReadAll(loggedBody)
	if err != nil || string(got) != "response payload" {
		t.Fatalf("logged response = %q, %v", got, err)
	}
	req.Header.Set("X-Test", "live")
	resp.Header.Set("X-Test", "live")
	if requestLog.Request.Header.Get("X-Test") != "" || responseLog.Response.Header.Get("X-Test") != "" {
		t.Fatal("logger shares live headers")
	}
}

type failingBody struct {
	read   bool
	closed bool
}

func (b *failingBody) Read(p []byte) (int, error) {
	if b.read {
		return 0, io.EOF
	}
	b.read = true
	return copy(p, "partial"), io.ErrUnexpectedEOF
}
func (b *failingBody) Close() error { b.closed = true; return nil }

func TestLogRequestReadErrorPreservesFailure(t *testing.T) {
	body := &failingBody{}
	req := httptest.NewRequest(http.MethodPost, "http://example.test/", nil)
	req.Body = body
	l := &Logger{asyncqueue: make(chan logTransaction, 1)}
	if err := l.LogRequest(req, types.UserData{}); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(req.Body)
	if string(got) != "partial" || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("forwarded body = %q, %v", got, err)
	}
	closeErr(t, req.Body)
	if !body.closed {
		t.Fatal("original body was not closed")
	}
	logged := <-l.asyncqueue
	_, _, err = logged.requestBody.snapshot()
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("captured error = %v", err)
	}
}

func TestLogResponsePreservesUpgradeBody(t *testing.T) {
	body := &failingBody{}
	resp := &http.Response{StatusCode: http.StatusSwitchingProtocols, Body: body}
	l := &Logger{asyncqueue: make(chan logTransaction, 1)}
	if err := l.LogResponse(resp, types.UserData{}); err != nil {
		t.Fatal(err)
	}
	if body.read || body.closed || resp.Body != body {
		t.Fatal("logging touched upgraded connection")
	}
}

func TestLogResponsePreservesBodyBeyondLogLimit(t *testing.T) {
	payload := strings.Repeat("response", 2048)
	resp := &http.Response{Body: io.NopCloser(strings.NewReader(payload))}
	l := &Logger{asyncqueue: make(chan logTransaction, 1)}
	if err := l.LogResponse(resp, types.UserData{}); err != nil {
		t.Fatal(err)
	}
	logged := <-l.asyncqueue
	got, err := io.ReadAll(resp.Body)
	closeErr(t, resp.Body)
	if err != nil || string(got) != payload {
		t.Fatalf("live body length = %d, error = %v", len(got), err)
	}
	body, _, err := logged.responseBody.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	got, err = io.ReadAll(body)
	if err != nil || len(got) != 4096 {
		t.Fatalf("logged body length = %d, error = %v", len(got), err)
	}
}

func TestLoggingDoesNotReadLiveBodies(t *testing.T) {
	for _, response := range []bool{false, true} {
		t.Run(fmt.Sprintf("response=%t", response), func(t *testing.T) {
			body := &failingBody{}
			l := &Logger{asyncqueue: make(chan logTransaction, 1)}
			var err error
			if response {
				err = l.LogResponse(&http.Response{Body: body}, types.UserData{})
			} else {
				req := httptest.NewRequest(http.MethodPost, "http://example.test/", nil)
				req.Body = body
				err = l.LogRequest(req, types.UserData{})
			}
			if err != nil || body.read {
				t.Fatalf("logging read live body: read=%t, error=%v", body.read, err)
			}
		})
	}
}

func TestHARLoggingPreservesMartianContext(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://example.test/", strings.NewReader("request payload"))
	_, remove, err := martian.TestContext(req, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	req.Header.Set("Content-Type", "text/plain")
	path := filepath.Join(t.TempDir(), "traffic.har")
	harLogger, err := har.NewLogger(path, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	l := &Logger{harLogger: harLogger, asyncqueue: make(chan logTransaction, 2)}
	if err := l.LogRequest(req, types.UserData{}); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(req.Body)
	closeErr(t, req.Body)
	if err != nil || string(got) != "request payload" {
		t.Fatalf("forwarded request = %q, %v", got, err)
	}
	resp := &http.Response{StatusCode: http.StatusOK, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Request: req, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("response payload"))}
	resp.Header.Set("Content-Type", "text/plain")
	if err := l.LogResponse(resp, types.UserData{}); err != nil {
		t.Fatal(err)
	}
	got, err = io.ReadAll(resp.Body)
	closeErr(t, resp.Body)
	if err != nil || string(got) != "response payload" {
		t.Fatalf("forwarded response = %q, %v", got, err)
	}
	close(l.asyncqueue)
	l.AsyncWrite()
	if err := harLogger.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(data) || !strings.Contains(string(data), "request payload") || !strings.Contains(string(data), base64.StdEncoding.EncodeToString([]byte("response payload"))) {
		t.Fatalf("HAR does not contain both bodies: %s", data)
	}
}

func TestBodyCaptureCloseUnblocksRead(t *testing.T) {
	reader, writer := io.Pipe()
	defer closeErr(t, writer)
	body := captureBody(reader, nil, 0)
	done := make(chan struct{})
	go func() { defer close(done); _, _ = io.Copy(io.Discard, body) }()
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not unblock Read")
	}
	_, _, _ = body.snapshot()
}

func TestBodyCaptureStreamsBeforeEOF(t *testing.T) {
	reader, writer := io.Pipe()
	defer closeErr(t, writer)
	body := captureBody(reader, nil, 0)
	defer closeErr(t, body)
	wrote := make(chan error, 1)
	go func() { _, err := io.WriteString(writer, "prefix"); wrote <- err }()
	got := make([]byte, len("prefix"))
	if _, err := io.ReadFull(body, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "prefix" {
		t.Fatalf("forwarded prefix = %q", got)
	}
	if err := <-wrote; err != nil {
		t.Fatal(err)
	}
	select {
	case <-body.done:
		t.Fatal("capture completed before EOF")
	default:
	}
	closeErr(t, writer)
	if _, err := io.Copy(io.Discard, body); err != nil {
		t.Fatal(err)
	}
	snapshot, _, err := body.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	got, err = io.ReadAll(snapshot)
	if err != nil || string(got) != "prefix" {
		t.Fatalf("snapshot = %q, %v", got, err)
	}
}

func TestHARLoggingErrorDoesNotStopRequestLogging(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://example.test/", strings.NewReader("payload"))
	req.Header.Set("Content-Type", "text/plain")
	_, remove, err := martian.TestContext(req, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	harLogger, err := har.NewLogger(filepath.Join(t.TempDir(), "traffic.har"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer closeErr(t, harLogger)
	l := &Logger{harLogger: harLogger, asyncqueue: make(chan logTransaction, 2)}
	if err := l.LogRequest(req, types.UserData{}); err != nil {
		t.Fatal(err)
	}
	// Reusing the same Martian request ID causes a HAR duplicate-ID error.
	if err := l.LogRequest(req, types.UserData{}); err != nil {
		t.Fatalf("HAR error escaped logger: %v", err)
	}
	got, err := io.ReadAll(req.Body)
	closeErr(t, req.Body)
	if err != nil || string(got) != "payload" {
		t.Fatalf("forwarded body = %q, %v", got, err)
	}
	if len(l.asyncqueue) != 2 {
		t.Fatal("HAR error prevented normal request logging")
	}
}

type trailerBody struct {
	trailer http.Header
	started chan struct{}
}

func (b *trailerBody) Read([]byte) (int, error) {
	close(b.started)
	for i := 0; i < 1000; i++ {
		b.trailer.Set(fmt.Sprintf("X-Trailer-%d", i), "value")
		runtime.Gosched()
	}
	return 0, io.EOF
}
func (*trailerBody) Close() error { return nil }

func TestLogEarlyResponseDuringRequestTrailers(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://example.test/", nil)
	req.Trailer = make(http.Header)
	original := &trailerBody{trailer: req.Trailer, started: make(chan struct{})}
	req.Body = original
	l := &Logger{asyncqueue: make(chan logTransaction, 101)}
	if err := l.LogRequest(req, types.UserData{}); err != nil {
		t.Fatal(err)
	}
	readDone := make(chan error, 1)
	go func() { _, err := io.Copy(io.Discard, req.Body); readDone <- err }()
	<-original.started
	for i := 0; i < 100; i++ {
		resp := &http.Response{Request: req, Body: http.NoBody}
		if err := l.LogResponse(resp, types.UserData{}); err != nil {
			t.Fatal(err)
		}
	}
	if err := <-readDone; err != nil {
		t.Fatal(err)
	}
	closeErr(t, req.Body)
	for i := 0; i < 101; i++ {
		transaction := <-l.asyncqueue
		_, trailer, err := transaction.requestBody.snapshot()
		if err != nil || trailer.Get("X-Trailer-999") != "value" {
			t.Fatalf("captured trailer missing, error = %v", err)
		}
	}
}

func TestLogRequestCapsLoggedBody(t *testing.T) {
	payload := strings.Repeat("request", 2048)
	req := httptest.NewRequest(http.MethodPost, "http://example.test/", strings.NewReader(payload))
	l := &Logger{asyncqueue: make(chan logTransaction, 1)}
	if err := l.LogRequest(req, types.UserData{}); err != nil {
		t.Fatal(err)
	}
	logged := <-l.asyncqueue
	got, err := io.ReadAll(req.Body)
	closeErr(t, req.Body)
	if err != nil || string(got) != payload {
		t.Fatalf("live body length = %d, error = %v", len(got), err)
	}
	body, _, err := logged.requestBody.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	got, err = io.ReadAll(body)
	if err != nil || len(got) != maxLoggedRequestBody {
		t.Fatalf("logged body length = %d, error = %v", len(got), err)
	}
}

func TestBodyCaptureSnapshotTimesOut(t *testing.T) {
	original := bodyCaptureWait
	bodyCaptureWait = 50 * time.Millisecond
	t.Cleanup(func() { bodyCaptureWait = original })

	reader, writer := io.Pipe()
	defer func() { _ = writer.Close() }()
	body := captureBody(reader, nil, 0)
	defer closeErr(t, body)

	started := time.Now()
	snapshot, _, err := body.snapshot()
	if !errors.Is(err, errCaptureTimeout) {
		t.Fatalf("snapshot error = %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("snapshot blocked on unread body")
	}
	got, err := io.ReadAll(snapshot)
	if err != nil || len(got) != 0 {
		t.Fatalf("timed out snapshot = %q, %v", got, err)
	}
}

func TestHARLoggingDoesNotReadLiveBody(t *testing.T) {
	body := &failingBody{}
	req := httptest.NewRequest(http.MethodPost, "http://example.test/", nil)
	req.Body = body
	req.Header.Set("Content-Type", "text/plain")
	_, remove, err := martian.TestContext(req, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	harLogger, err := har.NewLogger(filepath.Join(t.TempDir(), "traffic.har"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer closeErr(t, harLogger)
	l := &Logger{harLogger: harLogger, asyncqueue: make(chan logTransaction, 1)}
	if err := l.LogRequest(req, types.UserData{}); err != nil {
		t.Fatal(err)
	}
	if body.read || body.closed {
		t.Fatal("HAR logging consumed the live request body")
	}
}
