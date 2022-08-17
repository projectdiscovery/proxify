package main

// Parameter represents a parameter in the spec
type Parameter struct {
	Name        string  `json:"name,omitempty" yaml:"name,omitempty"`
	In          string  `json:"in,omitempty" yaml:"in,omitempty"`
	Description string  `json:"description,omitempty" yaml:"description,omitempty"`
	Required    bool    `json:"required,omitempty" yaml:"required,omitempty"`
	Schema      *Schema `json:"schema,omitempty" yaml:"schema,omitempty"`
}

// NewParameters creates a new parameters
func NewParameters(reqRes RequestResponse) []*Parameter {
	// get request parameters
	reqParams := reqRes.Request.URL.Query()
	var params []*Parameter
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
