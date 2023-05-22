package logger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/proxify/pkg/logger/elastic"
	"github.com/projectdiscovery/proxify/pkg/logger/file"
	"github.com/projectdiscovery/proxify/pkg/logger/kafka"
	stringsutil "github.com/projectdiscovery/utils/strings"

	"github.com/projectdiscovery/proxify/pkg/types"
)

const (
	dataWithNewLine    = "%s\n"
	dataWithoutNewLine = "%s"
)

type OptionsLogger struct {
	Verbosity    types.Verbosity
	OutputFolder string
	DumpRequest  bool
	DumpResponse bool
	OutputJsonl  bool
	MaxSize      int
	Elastic      *elastic.Options
	Kafka        *kafka.Options
}

type Store interface {
	Save(data types.OutputData) error
}

type Logger struct {
	options    *OptionsLogger
	asyncqueue chan types.OutputData
	jsonLogMap sync.Map
	Store      []Store
}

// NewLogger instance
func NewLogger(options *OptionsLogger) *Logger {
	logger := &Logger{
		options:    options,
		asyncqueue: make(chan types.OutputData, 1000),
	}
	if options.OutputJsonl {
		logger.jsonLogMap = sync.Map{}
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
	if options.OutputFolder != "" {
		store, err := file.New(&file.Options{
			OutputFolder: options.OutputFolder,
			OutputJsonl:  options.OutputJsonl,
		})
		if err != nil {
			gologger.Warning().Msgf("Error while creating file logger: %s", err)
		} else {
			logger.Store = append(logger.Store, store)

		}
	}

	go logger.AsyncWrite()

	return logger
}

// AsyncWrite data
func (l *Logger) AsyncWrite() {
	for outputdata := range l.asyncqueue {
		if len(l.Store) > 0 {
			if !l.options.DumpRequest && !l.options.DumpResponse {
				outputdata.PartSuffix = ""
			} else if l.options.DumpRequest && !outputdata.Userdata.HasResponse {
				outputdata.PartSuffix = ".request"
			} else if l.options.DumpResponse && outputdata.Userdata.HasResponse {
				outputdata.PartSuffix = ".response"
			} else {
				continue
			}
			outputdata.Name = fmt.Sprintf("%s%s-%s", outputdata.Userdata.Host, outputdata.PartSuffix, outputdata.Userdata.ID)
			if outputdata.Userdata.HasResponse && !(l.options.DumpRequest || l.options.DumpResponse) {
				if outputdata.Userdata.Match {
					outputdata.Name = outputdata.Name + ".match"
				}
			}
			outputdata.Format = dataWithoutNewLine
			if !strings.HasSuffix(string(outputdata.Data), "\n") {
				outputdata.Format = dataWithNewLine
			}

			outputdata.DataString = fmt.Sprintf(outputdata.Format, outputdata.Data)

			if l.options.MaxSize > 0 {
				outputdata.DataString = stringsutil.Truncate(outputdata.DataString, l.options.MaxSize)
			}

			for _, store := range l.Store {
				err := store.Save(outputdata)
				if err != nil {
					gologger.Warning().Msgf("Error while logging: %s", err)
				}
			}
		}
	}
}

// LogRequest and user data
func (l *Logger) LogRequest(req *http.Request, userdata types.UserData) error {
	reqdump, err := httputil.DumpRequest(req, true)
	if err != nil {
		return err
	}
	if l.options.OutputJsonl {
		outputData := types.HTTPRequestResponseLog{}
		if err := fillJsonRequestData(req, &outputData); err != nil {
			return err
		}
		l.jsonLogMap.Store(userdata.ID, outputData)
	}
	if (!l.options.OutputJsonl) && (l.options.OutputFolder != "" || l.options.Kafka.Addr != "" || l.options.Elastic.Addr != "") {
		l.asyncqueue <- types.OutputData{Data: reqdump, Userdata: userdata}
	}

	if l.options.Verbosity >= types.VerbosityVeryVerbose {
		contentType := req.Header.Get("Content-Type")
		b, _ := io.ReadAll(req.Body)
		if isASCIICheckRequired(contentType) && !govalidator.IsPrintableASCII(string(b)) {
			reqdump, _ = httputil.DumpRequest(req, false)
		}
		gologger.Silent().Msgf("%s", string(reqdump))
	}
	return nil
}

func isASCIICheckRequired(contentType string) bool {
	return stringsutil.ContainsAny(contentType, "application/octet-stream", "application/x-www-form-urlencoded")
}

// LogResponse and user data
func (l *Logger) LogResponse(resp *http.Response, userdata types.UserData) error {
	if resp == nil {
		return nil
	}
	respdump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return err
	}
	respdumpNoBody, err := httputil.DumpResponse(resp, false)
	if err != nil {
		return err
	}
	if l.options.OutputJsonl {
		defer l.jsonLogMap.Delete(userdata.ID)
		outputData := types.HTTPRequestResponseLog{}
		filledOutputReq, ok := l.jsonLogMap.Load(userdata.ID)
		if !ok {
			if err := fillJsonRequestData(resp.Request, &outputData); err != nil {
				return err
			}
		} else {
			outputData = filledOutputReq.(types.HTTPRequestResponseLog)
		}
		if err := fillJsonResponseData(resp, &outputData); err != nil {
			return err
		}
		respdump, err = json.Marshal(outputData)
		if err != nil {
			return err
		}
	}
	if l.options.OutputFolder != "" || l.options.Kafka.Addr != "" || l.options.Elastic.Addr != "" {
		l.asyncqueue <- types.OutputData{Data: respdump, Userdata: userdata}
	}
	if l.options.Verbosity >= types.VerbosityVeryVerbose {
		contentType := resp.Header.Get("Content-Type")
		bodyBytes := bytes.TrimPrefix(respdump, respdumpNoBody)
		if isASCIICheckRequired(contentType) && !govalidator.IsPrintableASCII(string(bodyBytes)) {
			gologger.Silent().Msgf("%s", string(respdumpNoBody))
		} else {
			gologger.Silent().Msgf("%s", string(respdump))
		}
	}
	return nil
}

// Close logger instance
func (l *Logger) Close() {
	close(l.asyncqueue)
}

func fillJsonRequestData(req *http.Request, outputData *types.HTTPRequestResponseLog) error {
	outputData.Timestamp = time.Now().Format(time.RFC3339)
	outputData.URL = req.URL.String()
	// Extract headers from the request
	reqHeaders := make(map[string]string)
	// basic header info
	reqHeaders["scheme"] = req.URL.Scheme
	reqHeaders["method"] = req.Method
	reqHeaders["path"] = req.URL.Path
	reqHeaders["host"] = req.URL.Host
	for key, values := range req.Header {
		reqHeaders[key] = strings.Join(values, ", ")
	}
	outputData.Request.Header = reqHeaders
	// Extract body from the request
	reqBody, err := io.ReadAll(req.Body)
	if err != nil {
		return err
	}
	defer req.Body.Close()
	req.Body = io.NopCloser(strings.NewReader(string(reqBody)))
	if err != nil {
		return err
	}
	outputData.Request.Body = string(reqBody)
	// Extract raw request
	reqdumpNoBody, err := httputil.DumpRequest(req, false)
	if err != nil {
		return err
	}
	outputData.Request.Raw = string(reqdumpNoBody)
	return nil
}

func fillJsonResponseData(resp *http.Response, outputData *types.HTTPRequestResponseLog) error {
	outputData.Timestamp = time.Now().Format(time.RFC3339)
	// Extract headers from the response
	respHeaders := make(map[string]string)
	for key, values := range resp.Header {
		respHeaders[key] = strings.Join(values, ", ")
	}
	outputData.Response.Header = respHeaders
	// Extract body from the response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	resp.Body = io.NopCloser(strings.NewReader(string(respBody)))
	outputData.Response.Body = string(respBody)
	// Extract raw response
	respdumpNoBody, err := httputil.DumpResponse(resp, false)
	if err != nil {
		return err
	}
	outputData.Response.Raw = string(respdumpNoBody)
	return nil
}
