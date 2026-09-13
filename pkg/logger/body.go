package logger

import (
	"bytes"
	"io"
	"net/http"
	"sync"
)

// bodyCapture observes forwarding reads. The logger only accesses data after done
// closes, so it never reads, replaces, or closes the live stream.
type bodyCapture struct {
	original        io.ReadCloser
	trailer         http.Header
	limit           int
	mu              sync.Mutex
	activeReads     int
	closed          bool
	complete        bool
	data            []byte
	err             error
	capturedTrailer http.Header
	done            chan struct{}
}

func captureBody(body io.ReadCloser, trailer http.Header, limit int) *bodyCapture {
	c := &bodyCapture{original: body, trailer: trailer, limit: limit, done: make(chan struct{})}
	if body == nil || body == http.NoBody {
		c.original = http.NoBody
		c.finish(nil)
	}

	return c
}

func (c *bodyCapture) Read(p []byte) (int, error) {
	c.mu.Lock()
	c.activeReads++
	c.mu.Unlock()

	n, err := c.original.Read(p)

	c.mu.Lock()
	c.activeReads--

	if !c.complete {
		size := n
		if c.limit > 0 && size > c.limit-len(c.data) {
			size = c.limit - len(c.data)
		}

		c.data = append(c.data, p[:size]...)
		if err != nil || c.closed || (c.limit > 0 && len(c.data) == c.limit) {
			c.finish(err)
		}
	}

	c.mu.Unlock()

	return n, err
}

func (c *bodyCapture) Close() error {
	// Close must unblock an active Read; never hold the capture lock around it.
	err := c.original.Close()

	c.mu.Lock()
	c.closed = true
	if c.activeReads == 0 {
		c.finish(nil)
	}
	c.mu.Unlock()

	return err
}

// finish runs under mu, or during construction before the wrapper is published.
func (c *bodyCapture) finish(err error) {
	if c.complete {
		return
	}

	c.complete = true
	if err != io.EOF {
		c.err = err
	}

	// Trailer values are final only after the forwarding reader reaches EOF.
	if err == io.EOF {
		c.capturedTrailer = c.trailer.Clone()
	}

	close(c.done)
}

func (c *bodyCapture) snapshot() (io.ReadCloser, http.Header, error) {
	<-c.done

	return io.NopCloser(bytes.NewReader(c.data)), c.capturedTrailer.Clone(), c.err
}
