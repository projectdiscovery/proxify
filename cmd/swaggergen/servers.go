package main

type Server struct {
	URL         string `json:"url"`
	Description string `json:"description"`
}

// NewServer creates a new server
func NewServer(url, description string) *Server {
	return &Server{
		URL:         url,
		Description: description,
	}
}
