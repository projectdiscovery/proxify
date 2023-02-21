package file

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/projectdiscovery/proxify/pkg/types"
	fileutil "github.com/projectdiscovery/utils/file"
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
	client := &Client{options: &Options{OutputFolder: option.OutputFolder}}
	return client, fileutil.CreateFolder(option.OutputFolder)
}

// Store writes the log to the file
func (c *Client) Save(data types.OutputData) error {
	// generate the file destination file name
	destFile := filepath.Join(c.options.OutputFolder, fmt.Sprintf("%s.%s", data.Name, "txt"))
	// if it's a response and file doesn't exist skip
	f, err := os.OpenFile(destFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	// write to file
	fmt.Fprint(f, data.DataString)
	return f.Close()
}
