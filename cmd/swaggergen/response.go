package main

// Response represents a response in the spec
type Response struct {
	Description string              `json:"description,omitempty" yaml:"description,omitempty"`
	Content     map[string]*Content `json:"content,omitempty" yaml:"content,omitempty"`
}

// NewResponse creates a new response
func NewResponse(reqRes RequestResponse) *Response {
	return &Response{
		Content: map[string]*Content{
			reqRes.Response.Header.Get("Content-Type"): NewContent(reqRes),
		},
	}
}
