package swaggergen

import "net/http"

// RequestResponse represents a request and response
type RequestResponse struct {
	Request  *http.Request
	Response *http.Response
}
