package logger

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/proxify/pkg/logger/elastic"
	"github.com/projectdiscovery/proxify/pkg/logger/file"
	"github.com/projectdiscovery/proxify/pkg/logger/kafka"
	"github.com/projectdiscovery/stringsutil"

	"github.com/projectdiscovery/proxify/pkg/types"
)

const (
	dataWithNewLine    = "%s\n\n"
	dataWithoutNewLine = "%s"
)

type OptionsLogger struct {
	Verbose      bool
	OutputFolder string
	DumpRequest  bool
	DumpResponse bool
	Elastic      *elastic.Options
	Kafka        *kafka.Options
}

type Store interface {
	Save(data types.OutputData) error
}

type Logger struct {
	options    *OptionsLogger
	asyncqueue chan types.OutputData
	Store      []Store
}

// NewLogger instance
func NewLogger(options *OptionsLogger) *Logger {
	logger := &Logger{
		options:    options,
		asyncqueue: make(chan types.OutputData, 1000),
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
	if l.options.OutputFolder != "" || l.options.Kafka.Addr != "" || l.options.Elastic.Addr != "" {
		l.asyncqueue <- types.OutputData{Data: reqdump, Userdata: userdata}
	}

	if l.options.Verbose {
		contentType := req.Header.Get("Content-Type")
		b, _ := ioutil.ReadAll(req.Body)
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
	if l.options.OutputFolder != "" || l.options.Kafka.Addr != "" || l.options.Elastic.Addr != "" {
		l.asyncqueue <- types.OutputData{Data: respdump, Userdata: userdata}
	}
	if l.options.Verbose {
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
