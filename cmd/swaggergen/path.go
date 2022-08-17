package main

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
