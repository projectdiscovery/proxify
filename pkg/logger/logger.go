package logger

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"os"
	"path"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/proxify/pkg/logger/elastic"
	"github.com/projectdiscovery/proxify/pkg/logger/kafka"

	"github.com/projectdiscovery/proxify/pkg/types"
	"github.com/projectdiscovery/stringsutil"
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
	Store(data string) error
}

type Logger struct {
	options       *OptionsLogger
	asyncqueue    chan types.OutputData
	ExternalStore []Store
}

// NewLogger instance
func NewLogger(options *OptionsLogger) *Logger {
	logger := &Logger{
		options:    options,
		asyncqueue: make(chan types.OutputData, 1000),
	}
	logger.createOutputFolder() //nolint

	if options.Elastic.Addr != "" {
		exporter, err := elastic.New(&elastic.Options{
			Addr:      options.Elastic.Addr,
			IndexName: options.Elastic.IndexName,
		})
		if err != nil {
			return nil
		}
		logger.ExternalStore = append(logger.ExternalStore, exporter)
	}

	if options.Kafka.Addr != "" {
		kfoptions := kafka.Options{
			Addr: options.Kafka.Addr,
		}
		exporter, err := kafka.New(&kfoptions)
		if err != nil {
			return nil
		}
		logger.ExternalStore = append(logger.ExternalStore, exporter)
	}

	go logger.AsyncWrite()

	return logger
}

func (l *Logger) createOutputFolder() error {
	if l.options.OutputFolder == "" {
		return nil
	}
	return os.MkdirAll(l.options.OutputFolder, 0755)
}

// AsyncWrite data
func (l *Logger) AsyncWrite() {
	var (
		format     string
		partSuffix string
		ext        string
	)
	for outputdata := range l.asyncqueue {
		if !l.options.DumpRequest && !l.options.DumpResponse {
			partSuffix = ""
			ext = ""
		} else if l.options.DumpRequest && !outputdata.Userdata.HasResponse {
			partSuffix = ".request"
			ext = ".txt"
		} else if l.options.DumpResponse && outputdata.Userdata.HasResponse {
			partSuffix = ".response"
			ext = ".txt"
		} else {
			continue
		}
		destFile := path.Join(l.options.OutputFolder, fmt.Sprintf("%s%s-%s%s", outputdata.Userdata.Host, partSuffix, outputdata.Userdata.ID, ext))
		// if it's a response and file doesn't exist skip
		f, err := os.OpenFile(destFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			continue
		}

		format = dataWithoutNewLine
		if !strings.HasSuffix(string(outputdata.Data), "\n") {
			format = dataWithNewLine
		}
		formatted := fmt.Sprintf(format, outputdata.Data)

		if len(l.ExternalStore) > 0 {
			for _, st := range l.ExternalStore {
				st.Store(formatted)
			}
		}

		fmt.Fprintf(f, format, outputdata.Data)
		fmt.Fprint(f, formatted)

		f.Close()
		if outputdata.Userdata.HasResponse && !(l.options.DumpRequest || l.options.DumpResponse) {
			outputFileName := destFile + ".txt"
			if outputdata.Userdata.Match {
				outputFileName = destFile + ".match.txt"
			}
			os.Rename(destFile, outputFileName) //nolint
		}
	}
}

// LogRequest and user data
func (l *Logger) LogRequest(req *http.Request, userdata types.UserData) error {
	reqdump, err := httputil.DumpRequest(req, true)
	if err != nil {
		return err
	}
	if l.options.OutputFolder != "" {
		l.asyncqueue <- types.OutputData{Data: reqdump, Userdata: userdata}
	}

	if l.options.Verbose {
		contentType := req.Header.Get("Content-Type")
		b, _ := ioutil.ReadAll(req.Body)
		if removeNonPrintableASCII(contentType) && !govalidator.IsPrintableASCII(string(b)) {
			reqdump, _ = httputil.DumpRequest(req, false)
		}
		gologger.Silent().Msgf("%s", string(reqdump))
	}
	return nil
}
func removeNonPrintableASCII(contentType string) bool {
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
	if l.options.OutputFolder != "" {
		l.asyncqueue <- types.OutputData{Data: respdump, Userdata: userdata}
	}
	if l.options.Verbose {
		contentType := resp.Header.Get("Content-Type")
		b, _ := ioutil.ReadAll(resp.Body)
		if removeNonPrintableASCII(contentType) && !govalidator.IsPrintableASCII(string(b)) {
			respdump, _ = httputil.DumpResponse(resp, false)
		}
		gologger.Silent().Msgf("%s", string(respdump))
	}
	return nil
}

// Close logger instance
func (l *Logger) Close() {
	close(l.asyncqueue)
}
