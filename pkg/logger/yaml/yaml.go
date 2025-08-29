package yaml

import (
	"os"

	"github.com/goccy/go-yaml"
	"github.com/projectdiscovery/proxify/pkg/types"
)

// YamlMultiDocWriter is a writer for yaml multi doc
type YamlMultiDocWriter struct {
	f   *os.File
	enc *yaml.Encoder
}

// NewYamlMultiDocWriter creates a new yaml multi doc writer
func NewYamlMultiDocWriter(filePath string) (*YamlMultiDocWriter, error) {
	file, err := os.Create(filePath)
	if err != nil {
		return nil, err
	}
	enc := yaml.NewEncoder(file, yaml.UseLiteralStyleIfMultiline(true), yaml.UseSingleQuote(true))
	return &YamlMultiDocWriter{f: file, enc: enc}, nil
}

// Write writes a http transaction to the file.
func (y *YamlMultiDocWriter) Write(data *types.HTTPRequestResponseLog) error {
	if err := y.enc.Encode(data); err != nil {
		return err
	}
	return nil
}

// Close closes the file writer.
func (y *YamlMultiDocWriter) Close() error {
	if y.enc != nil {
		_ = y.enc.Close()
	}
	if y.f != nil {
		_ = y.f.Close()
	}
	return nil
}
