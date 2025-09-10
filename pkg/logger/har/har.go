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

const FlushInterval = 10 * time.Second

type Writer struct {
	f     *os.File
	mutex *sync.Mutex
}

type Logger struct {
	martianHarLogger *har.Logger
	writer           *Writer
	done             chan struct{}
	wg               sync.WaitGroup
}

func NewLogger(filePath string, flushInterval time.Duration) (*Logger, error) {
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

	logger.wg.Add(1)
	go func(logger *Logger) {
		defer logger.wg.Done()
		ticker := time.NewTicker(flushInterval)
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

	// Check if file is empty (new file)
	fileInfo, err := w.f.Stat()
	if err != nil {
		return err
	}

	if fileInfo.Size() == 0 {
		// Write complete HAR structure for new file
		encoder := json.NewEncoder(w.f)
		encoder.SetIndent("", "  ")
		return encoder.Encode(harObj)
	}

	// For existing file, append entries efficiently
	return w.appendEntries(harObj.Log.Entries)
}

func (w *Writer) appendEntries(entries []*har.Entry) error {
	// Get current file size
	fileInfo, err := w.f.Stat()
	if err != nil {
		return err
	}

	// Read the last few bytes to find where to insert new entries
	// We need to find the position before the closing "]" of the entries array
	readSize := int64(200) // Read last 200 bytes, should be enough to find closing brackets
	if fileInfo.Size() < readSize {
		readSize = fileInfo.Size()
	}

	// Seek to position to read from
	seekPos := fileInfo.Size() - readSize
	if _, err := w.f.Seek(seekPos, io.SeekStart); err != nil {
		return err
	}

	// Read the last part of the file
	lastBytes := make([]byte, readSize)
	n, err := w.f.Read(lastBytes)
	if err != nil && err != io.EOF {
		return err
	}
	lastBytes = lastBytes[:n]

	// Find the position of the last "]" before the final "}"
	// This is where we need to insert new entries
	content := string(lastBytes)
	lastEntryEnd := -1

	// Look for the pattern "]\n}" which indicates end of entries array
	for i := len(content) - 3; i >= 0; i-- {
		if i+2 < len(content) && content[i:i+3] == "]\n}" {
			lastEntryEnd = i
			break
		}
	}

	// If we can't find the pattern, fall back to rewriting the whole file
	if lastEntryEnd == -1 {
		return w.rewriteFile(entries)
	}

	// Calculate the actual position in the file where we need to truncate
	truncatePos := seekPos + int64(lastEntryEnd)

	// Truncate the file at the position before the closing "]\n}"
	if err := w.f.Truncate(truncatePos); err != nil {
		return err
	}

	// Seek to the truncation point
	if _, err := w.f.Seek(truncatePos, io.SeekStart); err != nil {
		return err
	}

	// Write comma and newline if there were existing entries
	if truncatePos > 0 {
		if _, err := w.f.WriteString(",\n"); err != nil {
			return err
		}
	}

	// Write each new entry with proper formatting
	for i, entry := range entries {
		if i > 0 {
			if _, err := w.f.WriteString(",\n"); err != nil {
				return err
			}
		}

		// Marshal the entry with proper indentation
		entryBytes, err := json.MarshalIndent(entry, "    ", "  ")
		if err != nil {
			return err
		}

		// Adjust indentation to match HAR file format
		entryStr := string(entryBytes)
		// Replace the first 4 spaces with 2 spaces to match the entries array indentation
		if len(entryStr) > 4 && entryStr[:4] == "    " {
			entryStr = "  " + entryStr[4:]
		}

		if _, err := w.f.WriteString(entryStr); err != nil {
			return err
		}
	}

	// Write the closing brackets
	if _, err := w.f.WriteString("\n  ]\n}"); err != nil {
		return err
	}

	return nil
}

func (w *Writer) rewriteFile(entries []*har.Entry) error {
	// Fallback method: read existing file and rewrite
	// This is the old inefficient method, but kept as fallback
	if _, err := w.f.Seek(0, 0); err != nil {
		return err
	}

	decoder := json.NewDecoder(w.f)
	var existingHar har.HAR
	if err := decoder.Decode(&existingHar); err != nil && err != io.EOF {
		return err
	}

	// Merge entries
	if existingHar.Log != nil {
		existingHar.Log.Entries = append(existingHar.Log.Entries, entries...)
	} else {
		// This shouldn't happen in normal flow, but handle it
		existingHar = har.HAR{
			Log: &har.Log{
				Version: "1.2",
				Creator: &har.Creator{
					Name:    "proxify",
					Version: "1.0",
				},
				Entries: entries,
			},
		}
	}

	// Truncate and rewrite
	if err := w.f.Truncate(0); err != nil {
		return err
	}
	if _, err := w.f.Seek(0, 0); err != nil {
		return err
	}

	encoder := json.NewEncoder(w.f)
	encoder.SetIndent("", "  ")
	return encoder.Encode(existingHar)
}

func (l *Logger) Close() error {
	close(l.done)
	l.wg.Wait()
	if err := l.Flush(); err != nil {
		gologger.Error().Msgf("Could not flush HAR log on close: %s\n", err)
	}
	return l.writer.f.Close()
}
