package file

import (
	"fmt"
	"os"
	"path"

	"github.com/projectdiscovery/proxify/pkg/types"
)

// Options required for file export
type Options struct {
	// OutputFolder is the folder where the logs will be stored
	OutputFolder string `yaml:"output-folder"`
}

// Client type for file based logging
type Client struct {
	options *Options
}

// New creates and returns a new client for file based logging
func New(option *Options) (*Client, error) {
	return &Client{
		options: &Options{
			OutputFolder: option.OutputFolder,
		},
	}, CreateOutputFolder(option.OutputFolder)
}

// Store writes the log to the file
func (c *Client) Store(data types.OutputData) error {
	// generate the file destination file name
	destFile := path.Join(c.options.OutputFolder, fmt.Sprintf("%s.%s", data.Name, "txt"))
	// if it's a response and file doesn't exist skip
	f, err := os.OpenFile(destFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	// write to file
	fmt.Fprint(f, data.DataString)
	return f.Close()
}

// CreateOutputFolder creates the output folder if it doesn't exist
func CreateOutputFolder(outputFolder string) error {
	return os.MkdirAll(outputFolder, 0755)
}
