package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/proxify/pkg/swaggergen"
	fileutil "github.com/projectdiscovery/utils/file"
)

type Options struct {
	logDir     string
	outputSpec string
	api        string
}

func main() {
	options := &Options{}
	flagSet := goflags.NewFlagSet()

	flagSet.SetDescription(`SwaggerGen generates Swagger/OpenAPI specification using request and response files from a log directory`)

	flagSet.StringVar(&options.logDir, "log-dir", "", "path to proxify's output log directory")
	flagSet.StringVarP(&options.api, "api-host", "api", "", "API host (example: api.example.com)")
	flagSet.StringVarP(&options.outputSpec, "output-spec", "os", "", "file to store Swagger/OpenAPI specification (example: OpenAPI.yaml)")
	err := flagSet.Parse()
	if err != nil {
		gologger.Fatal().Msgf("Could not parse flags: %s", err)
	}
	if options.logDir == "" || options.outputSpec == "" || options.api == "" {
		gologger.Fatal().Msg("Please provide all required flags i.e, log-dir, output-spec, api-host")
	}
	_, err = url.Parse(options.api)
	if err != nil {
		gologger.Fatal().Msgf("Invalid API host: %s", err)
	}

	generator := NewGenerator(options)
	if err := generator.Generate(); err != nil {
		gologger.Fatal().Msg(err.Error())
	}

}

// Generator is the swagger spec generator
type Generator struct {
	RequestResponseList []swaggergen.RequestResponse
	Spec                *swaggergen.Spec
	Options             *Options
}

// NewGenerator creates a new generator instance
func NewGenerator(options *Options) *Generator {
	return &Generator{
		RequestResponseList: make([]swaggergen.RequestResponse, 0),
		Options:             options,
	}
}

// Generate generates a swagger specification from a directory of request/response logs
func (g *Generator) Generate() error {
	if err := g.ReadLog(); err != nil {
		return fmt.Errorf("error reading logs: %s", err)
	}
	if err := g.CreateSpec(); err != nil {
		return fmt.Errorf("error generating swagger specification: %s", err)
	}
	if err := g.WriteSpec(); err != nil {
		return fmt.Errorf("error writing data: %s", err)
	}
	return nil
}

// WriteSpec writes the spec to a yaml file
func (g *Generator) WriteSpec() error {
	// create/open openapi specification yaml file
	f, err := os.OpenFile(g.Options.outputSpec, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
	}()
	// write the spec to the file
	return yaml.NewEncoder(f).Encode(g.Spec)
}

// CreateSpec crseate the swagger spec from the generator's RequestResponse
func (g *Generator) CreateSpec() error {
	// check if spec file exists
	if fileutil.FileExists(g.Options.outputSpec) {
		// read the spec from the file
		f, err := os.Open(g.Options.outputSpec)
		if err != nil {
			return err
		}
		defer func() {
			_ = f.Close()
		}()
		g.Spec = &swaggergen.Spec{}
		if err := yaml.NewDecoder(f).Decode(g.Spec); err != nil {
			return err
		}
		g.Spec.UpdateSpec(g.Options.logDir, g.Options.api)
	} else {
		// create a new spec
		g.Spec = swaggergen.NewSpec(g.Options.logDir, g.Options.api)
	}

	for _, reqRes := range g.RequestResponseList {
		// filter out unrelated requests
		if reqRes.Request.Host == g.Options.api {
			g.Spec.AddPath(reqRes)
		}
	}
	return nil
}

// ReadLog reads the request/response list from logDir
func (g *Generator) ReadLog() error {
	// check if log directory exists
	if !fileutil.FolderExists(g.Options.logDir) {
		return fmt.Errorf("log directory (%s) does not exist", g.Options.logDir)
	}
	// read all files in directory
	return filepath.Walk(g.Options.logDir, func(path string, info fs.FileInfo, _ error) error {
		if info.IsDir() {
			return nil
		}
		// open file
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer func() {
			_ = f.Close()
		}()

		// read file
		buf := make([]byte, info.Size())
		_, err = f.Read(buf)
		if err != nil {
			return err
		}

		requestResponseString := string(buf)

		// split requestResponseString into request and response parts
		responseRegex := regexp.MustCompile("\n(HTTP\\/1\\.[0-1] (.|\n)*)")
		result := responseRegex.FindString(requestResponseString)
		result = strings.TrimPrefix(result, "\n")
		var requestResponse swaggergen.RequestResponse
		var requestError, responseError error
		requestResponse.Request, requestError = http.ReadRequest(bufio.NewReader(bytes.NewReader(buf)))
		requestResponse.Response, responseError = http.ReadResponse(bufio.NewReader(bytes.NewReader([]byte(result))), nil)

		if requestError != nil && responseError != nil {
			return fmt.Errorf("error reading request: %s, response: %s", requestError, responseError)
		}

		g.RequestResponseList = append(g.RequestResponseList, requestResponse)
		return nil
	})
}
