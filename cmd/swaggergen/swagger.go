package main

import (
	"bufio"
	"bytes"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

func main() {
	var logDir, outputSpec, api string
	flag.StringVar(&logDir, "log-dir", "", "log directory")
	flag.StringVar(&outputSpec, "spec", "", "output spec file")
	flag.StringVar(&api, "api", "", "api base url")
	flag.Parse()
	if logDir == "" || outputSpec == "" || api == "" {
		flag.Usage()
		os.Exit(1)
	}
	generator := NewGenerator()

	if err := generator.ReadLog(logDir); err != nil {
		log.Fatal(err)
	}
	if err := generator.CreateSpec(logDir, api); err != nil {
		log.Fatal(err)
	}
	if err := generator.WriteSpec(outputSpec); err != nil {
		log.Fatal(err)
	}
}

// Generator is the swagger spec generator
type Generator struct {
	RequestResponseList []RequestResponse
	Spec                *Spec
}

// RequestResponse represents a request and response
type RequestResponse struct {
	Request  *http.Request
	Response *http.Response
}

// NewGenerator creates a new generator instance
func NewGenerator() *Generator {
	return &Generator{
		RequestResponseList: make([]RequestResponse, 0),
	}
}

// WriteSpec writes the spec to a yaml file
func (r *Generator) WriteSpec(outputSpecFile string) error {
	// create/open openapi specification yaml file
	f, err := os.OpenFile(outputSpecFile, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		f.Close()
		return err
	}
	defer f.Close()
	// write the spec to the file
	return yaml.NewEncoder(f).Encode(r.Spec)
}

// CreateSpec crseate the swagger spec from the generator's RequestResponse
func (r *Generator) CreateSpec(logDir, api string) error {
	r.Spec = NewSpec(logDir, api)
	for _, reqRes := range r.RequestResponseList {
		// filter out unrelated requests
		if reqRes.Request.Host == api {
			r.Spec.AddPath(reqRes)
		}
	}
	return nil
}

// ReadLog reads the request/response list from logDir
func (r *Generator) ReadLog(logDir string) error {
	// check if log directory exists
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		return err
	}
	// read all files in directory
	return filepath.Walk(logDir, func(path string, info fs.FileInfo, _ error) error {
		if info.IsDir() {
			return nil
		}
		// open file
		f, err := os.Open(path)
		if err != nil {
			f.Close()
			return err
		}
		defer f.Close()

		// read file
		buf := make([]byte, info.Size())
		_, err = f.Read(buf)
		if err != nil {
			return err
		}

		requestResponseString := string(buf)

		// split requestResponseString into request and response parts
		responseRegex := regexp.MustCompile("\n(HTTP/1.1(.|\n)*)")
		result := responseRegex.FindString(requestResponseString)
		result = strings.TrimPrefix(result, "\n")
		var requestResponse RequestResponse

		// parse http request from string
		requestResponse.Request, err = http.ReadRequest(bufio.NewReader(bytes.NewReader(buf)))
		if err != nil {
			return err
		}
		// parse http response from string
		requestResponse.Response, err = http.ReadResponse(bufio.NewReader(bytes.NewReader([]byte(result))), nil)
		if err != nil {
			return err
		}

		r.RequestResponseList = append(r.RequestResponseList, requestResponse)
		return nil
	})
}
