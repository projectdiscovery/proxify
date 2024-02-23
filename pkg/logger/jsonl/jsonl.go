package jsonl

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/projectdiscovery/proxify/pkg/types"
)

// JsonLinesWriter is a writer for json lines
type JsonLinesWriter struct {
	f *os.File
}

// NewJsonLinesWriter creates a new json lines writer
func NewJsonLinesWriter(filePath string) (*JsonLinesWriter, error) {
	file, err := os.Create(filePath)
	if err != nil {
		return nil, err
	}
	return &JsonLinesWriter{f: file}, nil
}

// Write writes a http transaction to the file.
func (j *JsonLinesWriter) Write(data *types.HTTPRequestResponseLog) error {
	binx, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, _ = j.f.WriteString(strings.ReplaceAll(string(binx), "\n", "\\n")) // escape new lines
	_, _ = j.f.WriteString("\n")
	return nil
}

// Close closes the file writer.
func (j *JsonLinesWriter) Close() error {
	return j.f.Close()
}
