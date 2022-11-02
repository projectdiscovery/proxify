package swaggergen

import "net/http"

// Response represents a response in the spec
type Response struct {
	Description string              `json:"description,omitempty" yaml:"description,omitempty"`
	Content     map[string]*Content `json:"content,omitempty" yaml:"content,omitempty"`
}

// NewResponse creates a new response
func NewResponse(res *http.Response) *Response {
	var response *Response
	if res.Header != nil {
		response = &Response{
			Content: map[string]*Content{
				res.Header.Get("Content-Type"): NewContent(res),
			},
		}
	}
	return response
}

// UpdateResponse updates a response
func (r *Response) UpdateResponse(res *http.Response) {
	if res.Header != nil {
		if _, ok := r.Content[res.Header.Get("Content-Type")]; !ok {
			r.Content[res.Header.Get("Content-Type")] = NewContent(res)
		} else {
			r.Content[res.Header.Get("Content-Type")].UpdateContent(res)
		}
	}
}
