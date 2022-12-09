package swaggergen

// Operation represents an operation in the spec
type Method struct {
	Summary    string            `json:"summary,omitempty" yaml:"summary,omitempty"`
	Responses  map[int]*Response `json:"responses,omitempty" yaml:"responses,omitempty"`
	Parameters []*Parameter      `json:"parameters,omitempty" yaml:"parameters,omitempty"`
}

// NewMethod creates a new method
func NewMethod(reqRes RequestResponse) *Method {
	method := &Method{
		Responses:  map[int]*Response{},
		Parameters: NewParameters(reqRes.Request),
	}
	if reqRes.Response != nil {
		method.Responses = map[int]*Response{
			reqRes.Response.StatusCode: NewResponse(reqRes.Response),
		}
	}
	return method
}

// UpdateMethod updates a method
func (m *Method) UpdateMethod(reqRes RequestResponse) {
	if reqRes.Response != nil {
		if _, ok := m.Responses[reqRes.Response.StatusCode]; !ok {
			m.Responses[reqRes.Response.StatusCode] = NewResponse(reqRes.Response)
		} else {
			m.Responses[reqRes.Response.StatusCode].UpdateResponse(reqRes.Response)
		}
	}
	m.Parameters = NewParameters(reqRes.Request)
}
