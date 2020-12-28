package proxify

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"os"
	"path"
	"strings"

	"github.com/projectdiscovery/gologger"
)

const (
	dataWithNewLine    = "%s\n\n"
	dataWithoutNewLine = "%s"
)

type OptionsLogger struct {
	Verbose      bool
	OutputFolder string
}

type OutputData struct {
	userdata UserData
	data     []byte
}

type Logger struct {
	options    *OptionsLogger
	asyncqueue chan OutputData
}

func NewLogger(options *OptionsLogger) *Logger {
	logger := &Logger{
		options:    options,
		asyncqueue: make(chan OutputData, 1000),
	}
	_ = logger.createOutputFolder()
	go logger.AsyncWrite()
	return logger
}

func (l *Logger) createOutputFolder() error {
	if l.options.OutputFolder == "" {
		return nil
	}
	return os.MkdirAll(l.options.OutputFolder, 0755)
}

func (l *Logger) AsyncWrite() {
	var format string
	for outputdata := range l.asyncqueue {
		format = dataWithoutNewLine
		destFile := path.Join(l.options.OutputFolder, fmt.Sprintf("%s-%s", outputdata.userdata.host, outputdata.userdata.id))
		// if it's a response and file doesn't exist skip
		f, err := os.OpenFile(destFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			continue
		}

		if !strings.HasSuffix(string(outputdata.data), "\n") {
			format = dataWithNewLine
		}

		fmt.Fprintf(f, format, outputdata.data)

		f.Close()
		if outputdata.userdata.hasResponse {
			outputFileName := destFile + ".txt"
			if outputdata.userdata.match {
				outputFileName = destFile + ".match.txt"
			}
			os.Rename(destFile, outputFileName) //nolint
		}
	}
}

func (l *Logger) LogRequest(req *http.Request, userdata UserData) error {
	reqdump, err := httputil.DumpRequest(req, true)
	if err != nil {
		return err
	}
	if l.options.OutputFolder != "" {
		l.asyncqueue <- OutputData{data: reqdump, userdata: userdata}
	}

	if l.options.Verbose {
		gologger.Silentf("%s", string(reqdump))
	}

	return nil
}

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
		gologger.Silentf("%s", string(respdump))
	}
	return nil
}

func (l *Logger) Close() {
	close(l.asyncqueue)
}
