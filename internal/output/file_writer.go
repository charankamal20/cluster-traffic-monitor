package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/charankamal20/cluster-traffic-monitor/internal/events"
)

// TraceEntry represents a single HTTP trace log
type TraceEntry struct {
	ContentLength int64             `json:"content_length"`
	RemoteAddr    string            `json:"remote_addr"`
	Host          string            `json:"host"`
	Timestamp     time.Time         `json:"timestamp"`
	Method        string            `json:"method,omitempty"`
	URL           string            `json:"url,omitempty"`
	Status        string            `json:"status,omitempty"` // For responses
	DurationMs    int64             `json:"duration_ms,omitempty"`
	Src           string            `json:"src"`
	Dst           string            `json:"dst"`
	Headers       map[string]string `json:"headers,omitempty"`
	Body          string            `json:"body,omitempty"`
	Type          string            `json:"type"` // "REQUEST" or "RESPONSE"
	IsEncrypted   bool              `json:"is_encrypted"`
}

// CorrelatedTraceEntry represents a complete request-response pair
type CorrelatedTraceEntry struct {
	Timestamp       time.Time         `json:"timestamp"`
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	Status          string            `json:"status"`
	DurationMs      int64             `json:"duration_ms"`
	Src             string            `json:"src"`
	Dst             string            `json:"dst"`
	RequestHeaders  map[string]string `json:"request_headers,omitempty"`
	RequestBody     string            `json:"request_body,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	ResponseBody    string            `json:"response_body,omitempty"`
	IsEncrypted     bool              `json:"is_encrypted"`
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

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
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

// WriteCorrelated writes a correlated request-response pair
func (fw *FileWriter) WriteCorrelated(trace *events.CorrelatedTrace) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	entry := CorrelatedTraceEntry{
		Timestamp:       trace.Timestamp,
		Method:          trace.Method,
		URL:             trace.URL,
		Status:          trace.Status,
		DurationMs:      trace.DurationMs,
		Src:             trace.Src,
		Dst:             trace.Dst,
		RequestHeaders:  trace.RequestHeaders,
		RequestBody:     trace.RequestBody,
		ResponseHeaders: trace.ResponseHeaders,
		ResponseBody:    trace.ResponseBody,
		IsEncrypted:     trace.IsEncrypted,
	}

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
	// Signal flushLoop to stop first
	close(fw.stopCh)
	// Give it a moment to exit
	time.Sleep(100 * time.Millisecond)
	// Final flush
	fw.Flush()
	return fw.file.Close()
}
