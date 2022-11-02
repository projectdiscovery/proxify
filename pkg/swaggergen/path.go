package swaggergen

import (
	"strings"
)

// Path represents a path in the spec
type Path map[string]*Method

// NewPath creates a new path
func NewPath(reqRes RequestResponse) Path {
	return map[string]*Method{
		strings.ToLower(reqRes.Request.Method): NewMethod(reqRes),
	}
}

// UpdatePath updates a path
func (p Path) UpdatePath(reqRes RequestResponse) {
	if _, ok := p[strings.ToLower(reqRes.Request.Method)]; !ok {
		p[strings.ToLower(reqRes.Request.Method)] = NewMethod(reqRes)
	} else {
		p[strings.ToLower(reqRes.Request.Method)].UpdateMethod(reqRes)
	}
}
