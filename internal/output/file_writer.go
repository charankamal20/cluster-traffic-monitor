package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// TraceEntry represents a single HTTP trace log
type TraceEntry struct {
	Timestamp   time.Time         `json:"timestamp"`
	Method      string            `json:"method,omitempty"`
	URL         string            `json:"url,omitempty"`
	Status      string            `json:"status,omitempty"` // For responses
	DurationMs  int64             `json:"duration_ms,omitempty"`
	Src         string            `json:"src"`
	Dst         string            `json:"dst"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        string            `json:"body,omitempty"`
	Type        string            `json:"type"` // "REQUEST" or "RESPONSE"
	IsEncrypted bool              `json:"is_encrypted"`
}

// FileWriter handles buffered writing to a log file
type FileWriter struct {
	filePath string
	file     *os.File
	writer   *bufio.Writer
	mu       sync.Mutex
	stopCh   chan struct{}
}

// NewFileWriter parses the path and opens/creates the file
func NewFileWriter(path string) (*FileWriter, error) {
	// Ensure directory exists
	// Validating if it looks like a file path
	if path == "" {
		return nil, fmt.Errorf("empty file path")
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("opening trace log file: %w", err)
	}

	fw := &FileWriter{
		filePath: path,
		file:     f,
		writer:   bufio.NewWriter(f),
		stopCh:   make(chan struct{}),
	}

	// Background flush
	go fw.flushLoop()

	return fw, nil
}

func (fw *FileWriter) Write(entry TraceEntry) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	// Write NDJSON
	_, err = fw.writer.Write(data)
	if err != nil {
		return err
	}
	_, err = fw.writer.Write([]byte("\n"))
	return err
}

func (fw *FileWriter) flushLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			fw.Flush()
		case <-fw.stopCh:
			return
		}
	}
}

func (fw *FileWriter) Flush() {
	fw.mu.Lock()
	defer fw.mu.Unlock()
	fw.writer.Flush()
}

func (fw *FileWriter) Close() error {
	close(fw.stopCh)
	fw.Flush()
	return fw.file.Close()
}
