package main

const OpenApiVersion = "3.0.0"

// Spec represents openapi 3 specification
type Spec struct {
	OpenApi string          `json:"openapi"`
	Info    *Info           `json:"info"`
	Servers []*Server       `json:"servers"`
	Paths   map[string]Path `json:"paths"`
}

// NewSpec creates a new spec
func NewSpec(logDir, api string) *Spec {
	return &Spec{
		OpenApi: OpenApiVersion,
		Info:    NewInfo(logDir),
		Servers: []*Server{NewServer(api, "")},
		Paths:   map[string]Path{},
	}
}

// AddRequest adds a request to the spec
func (s *Spec) AddPath(reqRes RequestResponse) {
	path := reqRes.Request.URL.Path
	if _, ok := s.Paths[path]; !ok {
		s.Paths[path] = NewPath(reqRes)
	} else {
		s.Paths[path].UpdatePath(reqRes)
	}
}
