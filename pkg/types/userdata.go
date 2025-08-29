package types

import (
	"io"
	"net/http"
	"net/http/httputil"
	"strings"

	pdhttpUtils "github.com/projectdiscovery/utils/http"
)

// UserData is context used to identify a http
// transaction and its state like match, response etc.
type UserData struct {
	ID          string
	Match       *bool
	HasResponse bool
	Host        string
}

// HTTPTransaction is a struct for http transaction
// it contains data of every request/response obtained
// from proxy
type HTTPTransaction struct {
	Userdata   UserData
	RawData    []byte
	Data       []byte
	DataString string
	Name       string
	PartSuffix string
	Format     string

	Request  *http.Request
	Response *http.Response
}

// HTTPRequestResponseLog is a struct for http request and response log
// it is a processed version of http transaction for logging
// in more structured format than just raw bytes
type HTTPRequestResponseLog struct {
	Timestamp string        `json:"timestamp,omitempty"`
	URL       string        `json:"url,omitempty"`
	Request   *HTTPRequest  `json:"request,omitempty"`
	Response  *HTTPResponse `json:"response,omitempty"`
}

// HTTPRequest is a struct for http request
type HTTPRequest struct {
	Header map[string]string `json:"header,omitempty"`
	Body   string            `json:"body,omitempty"`
	Raw    string            `json:"raw,omitempty"`
}

// NewHttpRequestData creates a new HttpRequest with data extracted from an http.Request
func NewHttpRequestData(req *http.Request) (*HTTPRequest, error) {
	httpRequest := &HTTPRequest{
		Header: make(map[string]string),
	}

	// Extract headers from the request
	httpRequest.Header["scheme"] = req.URL.Scheme
	httpRequest.Header["method"] = req.Method
	httpRequest.Header["path"] = req.URL.Path
	httpRequest.Header["host"] = req.URL.Host
	for key, values := range req.Header {
		httpRequest.Header[key] = strings.Join(values, ", ")
	}

	// Extract body from the request
	reqBody, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = req.Body.Close()
	}()
	req.Body = io.NopCloser(strings.NewReader(string(reqBody)))
	httpRequest.Body = string(reqBody)

	// Extract raw request
	reqdumpNoBody, err := httputil.DumpRequest(req, true)
	if err != nil {
		return nil, err
	}
	httpRequest.Raw = string(reqdumpNoBody)

	return httpRequest, nil
}

// HTTPResponse is a struct for http response
type HTTPResponse struct {
	Header map[string]string `json:"header,omitempty"`
	Body   string            `json:"body,omitempty"`
	Raw    string            `json:"raw,omitempty"`
}

// NewHttpResponseData creates a new HttpResponse with data extracted from an http.Response
func NewHttpResponseData(resp *pdhttpUtils.ResponseChain) (*HTTPResponse, error) {
	httpResponse := &HTTPResponse{
		Header: make(map[string]string),
	}
	// Extract headers from the response
	for key, values := range resp.Response().Header {
		httpResponse.Header[key] = strings.Join(values, ", ")
	}
	httpResponse.Body = resp.Body().String()
	httpResponse.Raw = resp.Headers().String() // doesn't include body

	return httpResponse, nil
}
