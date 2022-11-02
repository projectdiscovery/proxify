package swaggergen

type Server struct {
	URL         string `json:"url,omitempty" yaml:"url,omitempty"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// NewServer creates a new server
func NewServer(url, description string) *Server {
	return &Server{
		URL:         url,
		Description: description,
	}
}
