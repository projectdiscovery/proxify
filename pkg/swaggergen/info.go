package swaggergen

type Info struct {
	Title       string `json:"title,omitempty" yaml:"title,omitempty"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	Version     string `json:"version,omitempty" yaml:"version,omitempty"`
}

// NewInfo creates a new info
func NewInfo(title string) *Info {
	return &Info{
		Title:   title,
		Version: "1.0.0",
	}
}

// UpdateInfo updates a info
func (i *Info) UpdateInfo(title string) {
	i.Title = i.Title + "," + title
}
