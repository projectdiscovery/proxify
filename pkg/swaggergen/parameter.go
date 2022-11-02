package swaggergen

import "net/http"

// Parameter represents a parameter in the spec
type Parameter struct {
	Name        string  `json:"name,omitempty" yaml:"name,omitempty"`
	In          string  `json:"in,omitempty" yaml:"in,omitempty"`
	Description string  `json:"description,omitempty" yaml:"description,omitempty"`
	Required    bool    `json:"required,omitempty" yaml:"required,omitempty"`
	Schema      *Schema `json:"schema,omitempty" yaml:"schema,omitempty"`
}

// NewParameters creates a new parameters
func NewParameters(req *http.Request) []*Parameter {
	var params []*Parameter
	if req.Body != nil {
		// add body parameter
		Schema := NewSchema(req.Body)
		if Schema != nil {
			params = append(params, &Parameter{
				Name:     "body",
				In:       "body",
				Required: true,
				Schema:   Schema,
			})
		}
	}
	// get request query parameters
	reqParams := req.URL.Query()
	// add query parameters
	for key, value := range reqParams {
		params = append(params, &Parameter{
			Name:        key,
			In:          "query",
			Schema:      &Schema{Type: "string"},
			Description: value[0],
			Required:    true,
		})
	}
	return params
}
