package swaggergen

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

// UpdateSpec updates a spec
func (s *Spec) UpdateSpec(logDir, api string) {
	s.Info.UpdateInfo(logDir)
	newServer := NewServer(api, "")
	for _, server := range s.Servers {
		if server.URL == newServer.URL {
			return
		}
	}
	s.Servers = append(s.Servers, newServer)
}

// AddPath adds a path to the spec
func (s *Spec) AddPath(reqRes RequestResponse) {
	path := reqRes.Request.URL.Path
	if _, ok := s.Paths[path]; !ok {
		s.Paths[path] = NewPath(reqRes)
	} else {
		s.Paths[path].UpdatePath(reqRes)
	}
}
