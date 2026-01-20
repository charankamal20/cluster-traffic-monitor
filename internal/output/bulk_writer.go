package output

import (
	"log/slog"
	"sync"
	"time"

	"github.com/charankamal20/cluster-traffic-monitor/internal/events"
)

// BulkWriter buffers trace writes and flushes them in batches
type BulkWriter struct {
	writer        *FileWriter
	buffer        []interface{}
	mu            sync.Mutex
	flushInterval time.Duration
	batchSize     int
	msgCh         chan interface{}
	stopCh        chan struct{}
	doneCh        chan struct{}
}

// NewBulkWriter creates a new bulk writer
func NewBulkWriter(writer *FileWriter, batchSize int, flushInterval time.Duration) *BulkWriter {
	if batchSize <= 0 {
		batchSize = 100
	}
	if flushInterval <= 0 {
		flushInterval = 5 * time.Second
	}

	bw := &BulkWriter{
		writer:        writer,
		buffer:        make([]interface{}, 0, batchSize),
		flushInterval: flushInterval,
		batchSize:     batchSize,
		msgCh:         make(chan interface{}, 1000), // Buffered channel to prevent blocking
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}

	go bw.run()

	return bw
}

// WriteCorrelated queues a trace for writing
func (bw *BulkWriter) WriteCorrelated(trace *events.CorrelatedTrace) {
	bw.enqueue(trace)
}

// WriteIgnored queues an ignored trace for writing
func (bw *BulkWriter) WriteIgnored(entry IgnoredTraceEntry) {
	bw.enqueue(entry)
}

// enqueue pushes message to channel non-blocking
func (bw *BulkWriter) enqueue(msg interface{}) {
	select {
	case bw.msgCh <- msg:
		// Queued successfully
	default:
		// Queue full, drop message to avoid blocking critical path
		slog.Warn("BulkWriter queue full, dropping message")
	}
}

// run handles the buffering and flushing logic
func (bw *BulkWriter) run() {
	ticker := time.NewTicker(bw.flushInterval)
	defer ticker.Stop()
	defer close(bw.doneCh)

	for {
		select {
		case msg := <-bw.msgCh:
			bw.buffer = append(bw.buffer, msg)
			if len(bw.buffer) >= bw.batchSize {
				bw.flush()
			}
		case <-ticker.C:
			bw.flush()
		case <-bw.stopCh:
			// Drain channel
		loop:
			for {
				select {
				case msg := <-bw.msgCh:
					bw.buffer = append(bw.buffer, msg)
				default:
					break loop
				}
			}
			bw.flush()
			return
		}
	}
}

// flush writes buffered traces to the underlying writer
func (bw *BulkWriter) flush() {
	if len(bw.buffer) == 0 {
		return
	}

	count := 0
	for _, msg := range bw.buffer {
		var err error
		switch v := msg.(type) {
		case *events.CorrelatedTrace:
			err = bw.writer.WriteCorrelated(v)
		case IgnoredTraceEntry:
			err = bw.writer.WriteIgnored(v)
		default:
			slog.Warn("Unknown message type in bulk buffer")
			continue
		}

		if err != nil {
			slog.Error("Error writing trace in bulk", "error", err)
		} else {
			count++
		}
	}

	// Flush the underlying bufio writer to ensure data hits the disk
	bw.writer.Flush()

	slog.Debug("Flushed bulk messages", "count", count)

	// Clear buffer (reusing capacity)
	bw.buffer = bw.buffer[:0]
}

// Close stops the bulk writer and flushes remaining items
func (bw *BulkWriter) Close() {
	close(bw.stopCh)
	<-bw.doneCh
	bw.writer.Close()
}
