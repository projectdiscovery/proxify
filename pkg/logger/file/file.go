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
	// OutputFile is the file where the jsonl logs will be stored
	OutputFile  string `yaml:"output-file"`
	OutputJsonl bool   `yaml:"output-jsonl"`
}

// Client type for file based logging
type Client struct {
	options *Options
}

// New creates and returns a new client for file based logging
func New(option *Options) (*Client, error) {
	client := &Client{options: option}
	if option.OutputFolder != "" {
		if err := fileutil.CreateFolder(option.OutputFolder); err != nil {
			return client, err
		}
	}
	if option.OutputFile != "" {
		file, err := os.Create(option.OutputFile)
		if err != nil {
			return client, err
		}
		defer func() {
			_ = file.Close()
		}()
	}
	return client, nil
}

// Store writes the log to the file
func (c *Client) Save(data types.HTTPTransaction) error {
	var err error
	logFile := fmt.Sprintf("%s.%s", data.Name, "txt")
	if c.options.OutputFolder != "" {
		err = c.writeToFile(filepath.Join(c.options.OutputFolder, logFile), string(data.RawData))
	}
	if c.options.OutputFile != "" && len(data.Data) > 0 {
		err = c.writeToFile(c.options.OutputFile, data.DataString)
	}
	return err
}

func (c *Client) writeToFile(filepath, content string) error {
	f, err := os.OpenFile(filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	// write to file
	if _, err := fmt.Fprint(f, content); err != nil {
		return err
	}
	return f.Close()
}
