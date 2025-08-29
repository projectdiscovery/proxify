package logger

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/proxify/pkg/logger/elastic"
	"github.com/projectdiscovery/proxify/pkg/logger/file"
	"github.com/projectdiscovery/proxify/pkg/logger/kafka"
	"github.com/projectdiscovery/utils/conversion"
	pdhttpUtils "github.com/projectdiscovery/utils/http"
	stringsutil "github.com/projectdiscovery/utils/strings"

	"github.com/projectdiscovery/proxify/pkg/types"
)

const (
	dataWithNewLine      = "%s\n"
	dataWithoutNewLine   = "%s"
	LoggerConfigFilename = "export-config.yaml"
)

type OptionsLogger struct {
	Verbosity    types.Verbosity
	OutputFolder string // when output is written to multiple files
	OutputFile   string // when output is written to single file
	OutputFormat string // jsonl or yaml
	DumpRequest  bool   // dump request to file
	DumpResponse bool   // dump response to file
	MaxSize      int    // max size of the output
	Elastic      *elastic.Options
	Kafka        *kafka.Options
}

type Store interface {
	Save(data types.HTTPTransaction) error
}

type Logger struct {
	options    *OptionsLogger
	asyncqueue chan types.HTTPTransaction
	Store      []Store
	sWriter    OutputFileWriter // sWriter is the structured writer
}

// NewLogger instance
func NewLogger(options *OptionsLogger) *Logger {
	logger := &Logger{
		options:    options,
		asyncqueue: make(chan types.HTTPTransaction, 1000),
	}
	if options.Elastic.Addr != "" {
		store, err := elastic.New(options.Elastic)
		if err != nil {
			gologger.Warning().Msgf("Error while creating elastic logger: %s", err)
		} else {
			logger.Store = append(logger.Store, store)
		}
	}
	if options.Kafka.Addr != "" {
		kfoptions := kafka.Options{
			Addr:  options.Kafka.Addr,
			Topic: options.Kafka.Topic,
		}
		store, err := kafka.New(&kfoptions)
		if err != nil {
			gologger.Warning().Msgf("Error while creating kafka logger: %s", err)
		} else {
			logger.Store = append(logger.Store, store)

		}
	}
	store, err := file.New(&file.Options{
		OutputFolder: options.OutputFolder,
	})
	if err != nil {
		gologger.Warning().Msgf("Error while creating file logger: %s", err)
	} else {
		logger.Store = append(logger.Store, store)
	}

	// setup structured writer
	if options.OutputFormat != "" {
		sWriter, err := NewOutputFileWriter(options.OutputFormat, options.OutputFile)
		if err != nil {
			gologger.Warning().Msgf("Error while creating structured writer: %s", err)
		} else {
			logger.sWriter = sWriter
		}
	}

	go logger.AsyncWrite()
	return logger
}

// LogRequest and user data
func (l *Logger) LogRequest(req *http.Request, userdata types.UserData) error {
	if req == nil {
		return nil
	}

	// send to writer channel
	l.asyncqueue <- types.HTTPTransaction{
		Userdata: userdata,
		Request:  req,
	}
	return nil
}

// LogResponse and user data
func (l *Logger) LogResponse(resp *http.Response, userdata types.UserData) error {
	if resp == nil {
		return nil
	}
	// send to writer channel
	l.asyncqueue <- types.HTTPTransaction{
		Userdata: userdata,
		Response: resp,
		Request:  resp.Request,
	}
	return nil
}

// AsyncWrite data
func (l *Logger) AsyncWrite() {
	for httpData := range l.asyncqueue {
		if httpData.Request == nil {
			// we can't do anything without request
			continue
		}
		// we have better options to handle this
		// i.e Buffer reuse and normalizing request/response body (removing encoding etc)
		reqDump, err := httputil.DumpRequest(httpData.Request, true)
		if err != nil {
			gologger.Warning().Msgf("Error while dumping request: %s", err)
		}

		// debug log request if true
		l.debugLogRequest(reqDump, httpData.Request)

		var respChain *pdhttpUtils.ResponseChain
		if httpData.Response != nil {
			respChainx := pdhttpUtils.NewResponseChain(httpData.Response, 4096)
			if err := respChainx.Fill(); err == nil {
				respChain = respChainx
			} else {
				gologger.Warning().Msgf("responseChain: Error while dumping response: %s", err)
			}
		}
		// debug log response if true
		if respChain != nil {
			if err := l.debugLogResponse(respChain); err != nil {
				gologger.Warning().Msgf("Error while logging response: %s", err)
			}
		}

		// first write to structured writer
		if l.sWriter != nil {
			func() {
				// if matchers were given only store those that match
				if httpData.Userdata.Match != nil {
					if !*httpData.Userdata.Match {
						return
					}
				}

				sData := &types.HTTPRequestResponseLog{
					Timestamp: time.Now().Format(time.RFC3339),
					URL:       httpData.Request.URL.String(),
				}
				defer func() {
					if sData.Response != nil {
						// write to structured writer with whatever data we have
						err := l.sWriter.Write(sData)
						if err != nil {
							gologger.Warning().Msgf("Error while logging: %s", err)
						}
					}
				}()
				sRequest, err := types.NewHttpRequestData(httpData.Request)
				if err != nil {
					gologger.Warning().Msgf("Error while creating request: %s", err)
					return
				}
				sData.Request = sRequest
				if respChain != nil {
					sResponse, err := types.NewHttpResponseData(respChain)
					if err != nil {
						gologger.Warning().Msgf("Error while creating response: %s", err)
					}
					sData.Response = sResponse
				}
			}()
		}

		// write to other writers
		if len(l.Store) > 0 {
			// write request first
			outputData := httpData
			// outputData.Data = reqDump
			outputData.RawData = reqDump
			outputData.Userdata.HasResponse = false
			l.storeWriter(outputData)

			// write response if available
			if respChain != nil {
				// outputData.Data = respChain.FullResponse().Bytes()
				outputData.RawData = respChain.FullResponse().Bytes()
				outputData.Userdata.HasResponse = true
				l.storeWriter(outputData)
			}
		}
	}
}

// Close logger instance
func (l *Logger) Close() {
	if l.sWriter != nil {
		_ = l.sWriter.Close()
	}
	close(l.asyncqueue)
}

// debugLogRequest logs the request to the console if debugging is enabled
func (l *Logger) debugLogRequest(reqdump []byte, req *http.Request) {
	if l.options.Verbosity >= types.VerbosityVeryVerbose {
		contentType := req.Header.Get("Content-Type")
		b, _ := io.ReadAll(req.Body)
		if isASCIICheckRequired(contentType) && !govalidator.IsPrintableASCII(string(b)) {
			reqdump, _ = httputil.DumpRequest(req, false)
		}
		gologger.Silent().Msgf("%s", string(reqdump))
	}
}

// debugLogResponse logs the response to the console if debugging is enabled
func (l *Logger) debugLogResponse(respChain *pdhttpUtils.ResponseChain) error {
	if l.options.Verbosity >= types.VerbosityVeryVerbose {
		contentType := respChain.Response().Header.Get("Content-Type")
		if isASCIICheckRequired(contentType) && !govalidator.IsPrintableASCII(conversion.String(respChain.Body().Bytes())) {
			gologger.Silent().Msgf("%s", respChain.Headers().String())
		} else {
			gologger.Silent().Msgf("%s", respChain.FullResponse().String())
		}
	}
	return nil
}

// storeWriter writes the data to the store (file, kafka, elastic)
// this can be refactored to make it more readable and scalable
// with improved interface and probably use of structure http data
// instead of raw bytes
func (l *Logger) storeWriter(outputdata types.HTTPTransaction) {
	if !l.options.DumpRequest && !l.options.DumpResponse {
		outputdata.PartSuffix = ""
	} else if l.options.DumpRequest && !outputdata.Userdata.HasResponse {
		outputdata.PartSuffix = ".request"
	} else if l.options.DumpResponse && outputdata.Userdata.HasResponse {
		outputdata.PartSuffix = ".response"
	} else {
		return
	}
	outputdata.Name = fmt.Sprintf("%s%s-%s", outputdata.Userdata.Host, outputdata.PartSuffix, outputdata.Userdata.ID)
	if outputdata.Userdata.HasResponse && (!l.options.DumpRequest && !l.options.DumpResponse) {
		if outputdata.Userdata.Match != nil && *outputdata.Userdata.Match {
			outputdata.Name = outputdata.Name + ".match"
		}
	}
	outputdata.Format = dataWithoutNewLine
	if !strings.HasSuffix(string(outputdata.Data), "\n") {
		outputdata.Format = dataWithNewLine
	}

	outputdata.DataString = fmt.Sprintf(outputdata.Format, outputdata.Data)
	if outputdata.Userdata.HasResponse {
		outputdata.Format = "\n" + outputdata.Format
	}
	outputdata.RawData = []byte(fmt.Sprintf(outputdata.Format, outputdata.RawData))

	if l.options.MaxSize > 0 {
		outputdata.DataString = stringsutil.Truncate(outputdata.DataString, l.options.MaxSize)
		outputdata.RawData = []byte(stringsutil.Truncate(string(outputdata.RawData), l.options.MaxSize))
	}
	for _, store := range l.Store {
		err := store.Save(outputdata)
		if err != nil {
			gologger.Warning().Msgf("Error while logging: %s", err)
		}
	}
}

func isASCIICheckRequired(contentType string) bool {
	return stringsutil.ContainsAny(contentType, "application/octet-stream", "application/x-www-form-urlencoded")
}
