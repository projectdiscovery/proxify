package logger

import (
	"errors"

	"github.com/projectdiscovery/proxify/pkg/logger/jsonl"
	"github.com/projectdiscovery/proxify/pkg/logger/yaml"
	"github.com/projectdiscovery/proxify/pkg/types"
)

var (
	_ OutputFileWriter = &jsonl.JsonLinesWriter{}
	// multi doc yaml writer with --- separator
	_ OutputFileWriter = &yaml.YamlMultiDocWriter{}

	ErrorInvalidFormat = errors.New("invalid format: expected jsonl or yaml")
)

// OutputFileWriter is an interface for writing structured
// data to a file.
type OutputFileWriter interface {
	// Write writes a http transaction to the file.
	Write(data *types.HTTPRequestResponseLog) error
	// Close closes the file writer.
	Close() error
}

// NewOutputFileWriter creates a new output file writer
func NewOutputFileWriter(format, filePath string) (OutputFileWriter, error) {
	switch format {
	case "jsonl":
		return jsonl.NewJsonLinesWriter(filePath)
	case "yaml":
		return yaml.NewYamlMultiDocWriter(filePath)
	default:
		return nil, ErrorInvalidFormat
	}
}
