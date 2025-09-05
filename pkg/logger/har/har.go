package har

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/martian/v3/har"
)

const flushPeriod = 10 * time.Second

type Writer struct {
	f     *os.File
	mutex *sync.Mutex
}

type Logger struct {
	martianHarLogger *har.Logger
	writer           *Writer
	done             chan struct{}
}

func NewLogger(filePath string) (*Logger, error) {
	martianHarLogger := har.NewLogger()
	writer, err := newWriter(filePath)
	if err != nil {
		return nil, err
	}

	logger := &Logger{
		martianHarLogger: martianHarLogger,
		writer:           writer,
		done:             make(chan struct{}),
	}

	go func(logger *Logger) {
		ticker := time.NewTicker(flushPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := writer.append(martianHarLogger.ExportAndReset()); err != nil {
					gologger.Error().Msgf("Could not write HAR log: %s\n", err)
				}
			case <-logger.done:
				return
			}
		}
	}(logger)

	return logger, nil
}

func newWriter(filePath string) (*Writer, error) {
	file, err := os.Create(filePath)
	if err != nil {
		return nil, err
	}
	return &Writer{f: file, mutex: &sync.Mutex{}}, nil
}

func (l *Logger) ModifyRequest(req *http.Request) error {
	return l.martianHarLogger.ModifyRequest(req)
}

func (l *Logger) ModifyResponse(resp *http.Response) error {
	return l.martianHarLogger.ModifyResponse(resp)
}

func (l *Logger) Flush() error {
	return l.writer.append(l.martianHarLogger.ExportAndReset())
}

func (w *Writer) append(harObj *har.HAR) error {
	if harObj == nil || harObj.Log == nil || len(harObj.Log.Entries) == 0 {
		return nil
	}

	w.mutex.Lock()
	defer w.mutex.Unlock()

	// read existing file
	if _, err := w.f.Seek(0, 0); err != nil {
		return err
	}
	decoder := json.NewDecoder(w.f)

	var existingHar har.HAR
	if err := decoder.Decode(&existingHar); err != nil && err != io.EOF {
		return err
	}

	// merge entries
	if existingHar.Log != nil {
		existingHar.Log.Entries = append(existingHar.Log.Entries, harObj.Log.Entries...)
	} else {
		existingHar = *harObj
	}

	// write merged file
	if err := w.f.Truncate(0); err != nil {
		return err
	}
	if _, err := w.f.Seek(0, 0); err != nil {
		return err
	}

	encoder := json.NewEncoder(w.f)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(existingHar); err != nil {
		return err
	}

	return nil
}

func (l *Logger) Close() error {
	close(l.done)
	if err := l.Flush(); err != nil {
		gologger.Error().Msgf("Could not flush HAR log on close: %s\n", err)
	}
	return l.writer.f.Close()
}
