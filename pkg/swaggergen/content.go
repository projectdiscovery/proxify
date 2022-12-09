package swaggergen

import "net/http"

// Content represents a content in the spec
type Content struct {
	Schema *Schema `json:"schema,omitempty" yaml:"schema,omitempty"`
}

// NewContent creates a new content
func NewContent(res *http.Response) *Content {
	var content *Content
	if res.Body != nil {
		content = &Content{
			Schema: NewSchema(res.Body),
		}
	}
	return content
}

// UpdateContent updates a content
func (c *Content) UpdateContent(res *http.Response) {
	if res.Body != nil {
		c.Schema = NewSchema(res.Body)
	}
}
