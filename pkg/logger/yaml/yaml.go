package yaml

import "github.com/projectdiscovery/proxify/pkg/types"

// YamlMultiDocWriter is a writer for yaml multi doc
type YamlMultiDocWriter struct {
}

// NewYamlMultiDocWriter creates a new yaml multi doc writer
func NewYamlMultiDocWriter(filePath string) (*YamlMultiDocWriter, error) {
	return &YamlMultiDocWriter{}, nil
}

// Write writes a http transaction to the file.
func (y *YamlMultiDocWriter) Write(data *types.HTTPRequestResponseLog) error {
	return nil
}

// Close closes the file writer.
func (y *YamlMultiDocWriter) Close() error {
	return nil
}
