package har

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/projectdiscovery/martian/v3/har"
	"github.com/stretchr/testify/require"
)

func TestNewLogger(t *testing.T) {
	tempDir := t.TempDir()
	tempFilePath := filepath.Join(tempDir, "test.har")

	logger, err := NewLogger(tempFilePath, FlushInterval)
	require.NoError(t, err)
	require.NotNil(t, logger)
	defer func() {
		require.NoError(t, logger.Close())
	}()

	// Check that the logger and its components are initialized
	require.NotNil(t, logger.martianHarLogger)
	require.NotNil(t, logger.writer)
	require.NotNil(t, logger.done)

	// Check that the file was created
	_, err = os.Stat(tempFilePath)
	require.NoError(t, err)
}

func TestAppend(t *testing.T) {
	tempDir := t.TempDir()
	tempFilePath := filepath.Join(tempDir, "test.har")

	writer, err := newWriter(tempFilePath)
	require.NoError(t, err)
	require.NotNil(t, writer)
	defer func() {
		require.NoError(t, writer.f.Close())
	}()

	// First append
	har1 := &har.HAR{
		Log: &har.Log{
			Entries: []*har.Entry{
				{Request: &har.Request{URL: "https://example.com/1"}},
			},
		},
	}
	err = writer.append(har1)
	require.NoError(t, err)

	// Second append
	har2 := &har.HAR{
		Log: &har.Log{
			Entries: []*har.Entry{
				{Request: &har.Request{URL: "https://example.com/2"}},
			},
		},
	}
	err = writer.append(har2)
	require.NoError(t, err)

	// Read the file and verify its content
	fileContent, err := os.ReadFile(tempFilePath)
	require.NoError(t, err)

	var resultHar har.HAR
	err = json.Unmarshal(fileContent, &resultHar)
	require.NoError(t, err)

	// Verify the entries
	require.Len(t, resultHar.Log.Entries, 2)
	require.Equal(t, "https://example.com/1", resultHar.Log.Entries[0].Request.URL)
	require.Equal(t, "https://example.com/2", resultHar.Log.Entries[1].Request.URL)
}

func TestLoggerLifecycle(t *testing.T) {
	tempDir := t.TempDir()
	tempFilePath := filepath.Join(tempDir, "test.har")

	// Use a shorter flush period for testing
	flushInterval := 200 * time.Millisecond

	logger, err := NewLogger(tempFilePath, flushInterval)
	require.NoError(t, err)
	require.NotNil(t, logger)

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	var harResult har.HAR

	// Simulate some requests and responses by calling the logger directly
	// This is not ideal, but it's the simplest way to test the flushing
	// without setting up a full martian proxy.
	request1 := mustNewRequest(t, "GET", server.URL+"/req1")
	response1 := &http.Response{Request: request1}
	request2 := mustNewRequest(t, "POST", server.URL+"/req2")
	response2 := &http.Response{Request: request2}
	require.NoError(t, logger.martianHarLogger.RecordRequest("1", request1))
	require.NoError(t, logger.martianHarLogger.RecordResponse("1", response1))
	require.NoError(t, logger.martianHarLogger.RecordRequest("2", request2))
	require.NoError(t, logger.martianHarLogger.RecordResponse("2", response2))

	// Wait for the background goroutine to flush
	require.Eventually(t, func() bool {
		fileContent, err := os.ReadFile(tempFilePath)
		if err != nil {
			return false
		}
		var harResult har.HAR
		if err := json.Unmarshal(fileContent, &harResult); err != nil {
			return false
		}
		return len(harResult.Log.Entries) == 2
	}, time.Second, 50*time.Millisecond)

	// Check the content after the periodic flush
	fileContent, err := os.ReadFile(tempFilePath)
	require.NoError(t, err)

	err = json.Unmarshal(fileContent, &harResult)
	require.NoError(t, err)
	require.Len(t, harResult.Log.Entries, 2)
	require.Equal(t, server.URL+"/req1", harResult.Log.Entries[0].Request.URL)
	require.Equal(t, server.URL+"/req2", harResult.Log.Entries[1].Request.URL)

	// Simulate more requests and then close the logger
	request3 := mustNewRequest(t, "PUT", server.URL+"/req3")
	response3 := &http.Response{Request: request3}
	require.NoError(t, logger.martianHarLogger.RecordRequest("3", request3))
	require.NoError(t, logger.martianHarLogger.RecordResponse("3", response3))

	require.NoError(t, logger.Close())

	// Check the final content after Close calls Flush
	fileContent, err = os.ReadFile(tempFilePath)
	require.NoError(t, err)

	err = json.Unmarshal(fileContent, &harResult)
	require.NoError(t, err)
	require.Len(t, harResult.Log.Entries, 3)
	require.Equal(t, server.URL+"/req1", harResult.Log.Entries[0].Request.URL)
	require.Equal(t, server.URL+"/req2", harResult.Log.Entries[1].Request.URL)
	require.Equal(t, server.URL+"/req3", harResult.Log.Entries[2].Request.URL)
}

func mustNewRequest(t *testing.T, method, url string) *http.Request {
	req, err := http.NewRequest(method, url, nil)
	require.NoError(t, err)
	return req
}
