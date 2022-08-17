package main

// Content represents a content in the spec
type Content struct {
	Schema *Schema `json:"schema,omitempty" yaml:"schema,omitempty"`
}

// NewContent creates a new content
func NewContent(reqRes RequestResponse) *Content {
	return &Content{
		Schema: NewSchema(reqRes),
	}
}
