package main

// Operation represents an operation in the spec
type Method struct {
	Summary    string            `json:"summary,omitempty" yaml:"summary,omitempty"`
	Responses  map[int]*Response `json:"responses,omitempty" yaml:"responses,omitempty"`
	Parameters []*Parameter      `json:"parameters,omitempty" yaml:"parameters,omitempty"`
}

// NewMethod creates a new method
func NewMethod(reqRes RequestResponse) *Method {
	return &Method{
		Responses: map[int]*Response{
			reqRes.Response.StatusCode: NewResponse(reqRes),
		},
		Parameters: NewParameters(reqRes),
	}
}
