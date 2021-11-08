package proxify

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
}

type OutputData struct {
	userdata UserData
	data     []byte
}

type Logger struct {
	options    *OptionsLogger
	asyncqueue chan OutputData
}

// NewLogger instance
func NewLogger(options *OptionsLogger) *Logger {
	logger := &Logger{
		options:    options,
		asyncqueue: make(chan OutputData, 1000),
	}
	logger.createOutputFolder() //nolint
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
		} else if l.options.DumpRequest && !outputdata.userdata.hasResponse {
			partSuffix = ".request"
			ext = ".txt"
		} else if l.options.DumpResponse && outputdata.userdata.hasResponse {
			partSuffix = ".response"
			ext = ".txt"
		} else {
			continue
		}
		destFile := path.Join(l.options.OutputFolder, fmt.Sprintf("%s%s-%s%s", outputdata.userdata.host, partSuffix, outputdata.userdata.id, ext))
		// if it's a response and file doesn't exist skip
		f, err := os.OpenFile(destFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			continue
		}

		format = dataWithoutNewLine
		if !strings.HasSuffix(string(outputdata.data), "\n") {
			format = dataWithNewLine
		}

		fmt.Fprintf(f, format, outputdata.data)

		f.Close()
		if outputdata.userdata.hasResponse && !(l.options.DumpRequest || l.options.DumpResponse) {
			outputFileName := destFile + ".txt"
			if outputdata.userdata.match {
				outputFileName = destFile + ".match.txt"
			}
			os.Rename(destFile, outputFileName) //nolint
		}
	}
}

// LogRequest and user data
func (l *Logger) LogRequest(req *http.Request, userdata UserData) error {
	reqdump, err := httputil.DumpRequest(req, true)
	if err != nil {
		return err
	}
	if l.options.OutputFolder != "" {
		l.asyncqueue <- OutputData{data: reqdump, userdata: userdata}
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
func (l *Logger) LogResponse(resp *http.Response, userdata UserData) error {
	if resp == nil {
		return nil
	}
	respdump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return err
	}
	if l.options.OutputFolder != "" {
		l.asyncqueue <- OutputData{data: respdump, userdata: userdata}
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
