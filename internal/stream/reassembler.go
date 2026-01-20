package stream

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/charankamal20/cluster-traffic-monitor/internal/events"
	"github.com/charankamal20/cluster-traffic-monitor/internal/grpc"
	"github.com/charankamal20/cluster-traffic-monitor/internal/http2"
)

// StreamKey uniquely identifies a TCP stream
type StreamKey struct {
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
}

// Stream represents an ongoing TCP stream with protocol state
type Stream struct {
	Key          StreamKey
	Buffer       *bytes.Buffer
	LastSeen     time.Time
	MessageCount int
	Protocol     uint8

	// HTTP/2 specific state
	http2Parser *http2.Parser

	// gRPC specific state
	grpcParser *grpc.Parser

	// Statistics
	BytesReceived uint64
	BytesDropped  uint64
}

// Message represents a complete HTTP message (any protocol)
type Message struct {
	Data     []byte
	Protocol uint8
	Metadata MessageMetadata
}

// MessageMetadata holds additional message information
type MessageMetadata struct {
	StreamID    uint32 // For HTTP/2/gRPC
	IsEndStream bool   // For HTTP/2/gRPC
	IsRequest   bool
	Service     string // For gRPC
	Method      string // For gRPC/HTTP
}

// Reassembler assembles TCP streams from chunks with protocol awareness
type Reassembler struct {
	streams       map[StreamKey]*Stream
	mu            sync.RWMutex
	timeout       time.Duration
	maxBufferSize int
	stats         ReassemblerStats
	statsMu       sync.RWMutex
}

// ReassemblerStats tracks reassembler performance
type ReassemblerStats struct {
	TotalStreams      uint64
	ActiveStreams     uint64
	CompletedMessages uint64
	DroppedMessages   uint64
	BytesProcessed    uint64
	ParseErrors       uint64
}

// NewReassembler creates a new stream reassembler
func NewReassembler(timeout time.Duration) *Reassembler {
	r := &Reassembler{
		streams:       make(map[StreamKey]*Stream),
		timeout:       timeout,
		maxBufferSize: 1 << 20, // 1MB per stream
	}
	go r.cleanupLoop()
	go r.statsLoop()
	return r
}

// AddChunk adds data to the stream and returns complete messages
func (r *Reassembler) AddChunk(key StreamKey, data []byte, direction uint8, protocol uint8) []Message {
	r.mu.Lock()
	defer r.mu.Unlock()

	stream, exists := r.streams[key]
	if !exists {
		stream = &Stream{
			Key:      key,
			Buffer:   bytes.NewBuffer(nil),
			Protocol: protocol,
		}

		// Initialize protocol-specific parsers
		switch protocol {
		case events.ProtoHTTP2:
			stream.http2Parser = http2.NewParser()
		case events.ProtoGRPC:
			stream.http2Parser = http2.NewParser() // gRPC uses HTTP/2 frames
			stream.grpcParser = grpc.NewParser()
		}

		r.streams[key] = stream
		r.statsMu.Lock()
		r.stats.TotalStreams++
		r.stats.ActiveStreams++
		r.statsMu.Unlock()
	}

	// Update protocol if it changed (e.g., upgraded from HTTP/1 to HTTP/2)
	if stream.Protocol == events.ProtoUnknown && protocol != events.ProtoUnknown {
		stream.Protocol = protocol
		if protocol == events.ProtoHTTP2 {
			stream.http2Parser = http2.NewParser()
		} else if protocol == events.ProtoGRPC {
			stream.http2Parser = http2.NewParser()
			stream.grpcParser = grpc.NewParser()
		}
	}

	// Check buffer size limit
	if stream.Buffer.Len()+len(data) > r.maxBufferSize {
		slog.Warn("Stream buffer full, dropping data",
			"stream", key,
			"buffer_size", stream.Buffer.Len(),
			"new_data", len(data))

		stream.BytesDropped += uint64(len(data))
		r.statsMu.Lock()
		r.stats.DroppedMessages++
		r.statsMu.Unlock()

		// Reset buffer to recover
		stream.Buffer.Reset()
		return nil
	}

	// Append data
	stream.Buffer.Write(data)
	stream.LastSeen = time.Now()
	stream.BytesReceived += uint64(len(data))

	r.statsMu.Lock()
	r.stats.BytesProcessed += uint64(len(data))
	r.statsMu.Unlock()

	// Extract messages based on protocol
	var messages []Message
	var err error

	switch stream.Protocol {
	case events.ProtoHTTP1:
		messages = r.extractHTTP1Messages(stream)
	case events.ProtoHTTP2:
		messages, err = r.extractHTTP2Messages(stream)
	case events.ProtoGRPC:
		messages, err = r.extractGRPCMessages(stream)
	default:
		// Unknown protocol, try to detect
		if r.tryDetectProtocol(stream) {
			// Retry extraction with detected protocol
			return r.AddChunk(key, []byte{}, direction, stream.Protocol)
		}
	}

	if err != nil {
		slog.Debug("Error extracting messages",
			"stream", key,
			"protocol", stream.Protocol,
			"error", err)
		r.statsMu.Lock()
		r.stats.ParseErrors++
		r.statsMu.Unlock()
	}

	r.statsMu.Lock()
	r.stats.CompletedMessages += uint64(len(messages))
	r.statsMu.Unlock()

	return messages
}

// tryDetectProtocol attempts to detect protocol from buffer contents
func (r *Reassembler) tryDetectProtocol(stream *Stream) bool {
	buf := stream.Buffer.Bytes()
	if len(buf) < 24 {
		return false // Need more data
	}

	// Check for HTTP/2 preface
	if http2.IsHTTP2Preface(buf) {
		stream.Protocol = events.ProtoHTTP2
		stream.http2Parser = http2.NewParser()
		slog.Debug("Detected HTTP/2 protocol", "stream", stream.Key)
		return true
	}

	// Check for HTTP/1.x
	if bytes.HasPrefix(buf, []byte("GET ")) ||
		bytes.HasPrefix(buf, []byte("POST ")) ||
		bytes.HasPrefix(buf, []byte("HTTP/")) {
		stream.Protocol = events.ProtoHTTP1
		slog.Debug("Detected HTTP/1.x protocol", "stream", stream.Key)
		return true
	}

	return false
}

// extractHTTP1Messages extracts HTTP/1.x messages
func (r *Reassembler) extractHTTP1Messages(stream *Stream) []Message {
	var messages []Message

	for {
		buf := stream.Buffer.Bytes()
		if len(buf) == 0 {
			break
		}

		// Detect message type
		isRequest := bytes.HasPrefix(buf, []byte("GET ")) ||
			bytes.HasPrefix(buf, []byte("POST ")) ||
			bytes.HasPrefix(buf, []byte("PUT ")) ||
			bytes.HasPrefix(buf, []byte("DELETE ")) ||
			bytes.HasPrefix(buf, []byte("PATCH ")) ||
			bytes.HasPrefix(buf, []byte("HEAD ")) ||
			bytes.HasPrefix(buf, []byte("OPTIONS "))

		isResponse := bytes.HasPrefix(buf, []byte("HTTP/"))

		if !isRequest && !isResponse {
			// Invalid data, clear buffer
			slog.Debug("Invalid HTTP/1 data, clearing buffer",
				"stream", stream.Key,
				"first_bytes", string(buf[:min(20, len(buf))]))
			stream.Buffer.Reset()
			break
		}

		// Find end of headers
		idx := bytes.Index(buf, []byte("\r\n\r\n"))
		if idx == -1 {
			// Incomplete headers
			break
		}

		headerEnd := idx + 4
		bodyLen := getContentLength(buf[:headerEnd])

		// Handle chunked encoding for responses
		if isResponse && isChunkedEncoding(buf[:headerEnd]) {
			completeLen := findChunkedEnd(buf)
			if completeLen == -1 {
				break // Incomplete chunked body
			}
			msg := make([]byte, completeLen)
			copy(msg, buf[:completeLen])
			messages = append(messages, Message{
				Data:     msg,
				Protocol: events.ProtoHTTP1,
				Metadata: MessageMetadata{IsRequest: isRequest},
			})
			stream.Buffer = bytes.NewBuffer(buf[completeLen:])
			stream.MessageCount++
			continue
		}

		// Handle Content-Length based messages
		if bodyLen > 0 {
			totalLen := headerEnd + bodyLen
			if len(buf) < totalLen {
				break // Incomplete body
			}
			msg := make([]byte, totalLen)
			copy(msg, buf[:totalLen])
			messages = append(messages, Message{
				Data:     msg,
				Protocol: events.ProtoHTTP1,
				Metadata: MessageMetadata{IsRequest: isRequest},
			})
			stream.Buffer = bytes.NewBuffer(buf[totalLen:])
			stream.MessageCount++
		} else {
			// No body, just headers
			msg := make([]byte, headerEnd)
			copy(msg, buf[:headerEnd])
			messages = append(messages, Message{
				Data:     msg,
				Protocol: events.ProtoHTTP1,
				Metadata: MessageMetadata{IsRequest: isRequest},
			})
			stream.Buffer = bytes.NewBuffer(buf[headerEnd:])
			stream.MessageCount++
		}
	}

	return messages
}

// extractHTTP2Messages extracts HTTP/2 messages
func (r *Reassembler) extractHTTP2Messages(stream *Stream) ([]Message, error) {
	if stream.http2Parser == nil {
		return nil, fmt.Errorf("HTTP/2 parser not initialized")
	}

	buf := stream.Buffer.Bytes()
	h2msgs, remaining, err := stream.http2Parser.ParseFrames(buf)
	if err != nil {
		// On parse error, clear buffer to recover
		stream.Buffer.Reset()
		return nil, fmt.Errorf("HTTP/2 parse error: %w", err)
	}

	// Update buffer with remaining data
	stream.Buffer = bytes.NewBuffer(remaining)

	// Convert to our Message type
	var messages []Message
	for _, h2msg := range h2msgs {
		data := serializeHTTP2Message(h2msg)
		messages = append(messages, Message{
			Data:     data,
			Protocol: events.ProtoHTTP2,
			Metadata: MessageMetadata{
				StreamID:    h2msg.StreamID,
				IsEndStream: h2msg.IsEndStream,
				IsRequest:   h2msg.IsRequest,
				Method:      h2msg.Method,
			},
		})
		stream.MessageCount++
	}

	return messages, nil
}

// extractGRPCMessages extracts gRPC messages
func (r *Reassembler) extractGRPCMessages(stream *Stream) ([]Message, error) {
	if stream.http2Parser == nil || stream.grpcParser == nil {
		return nil, fmt.Errorf("gRPC parsers not initialized")
	}

	// First parse HTTP/2 frames
	buf := stream.Buffer.Bytes()
	h2msgs, remaining, err := stream.http2Parser.ParseFrames(buf)
	if err != nil {
		stream.Buffer.Reset()
		return nil, fmt.Errorf("HTTP/2 parse error in gRPC stream: %w", err)
	}

	stream.Buffer = bytes.NewBuffer(remaining)

	var messages []Message
	for _, h2msg := range h2msgs {
		// Parse gRPC message from HTTP/2 DATA frames
		if len(h2msg.Body) > 0 {
			grpcMsg, bytesRead, err := stream.grpcParser.ParseMessage(h2msg.Body, h2msg.Headers)
			if err != nil {
				slog.Debug("gRPC parse error",
					"stream", stream.Key,
					"error", err)
				continue
			}

			// Serialize for logging
			data := serializeGRPCMessage(grpcMsg, h2msg)
			messages = append(messages, Message{
				Data:     data,
				Protocol: events.ProtoGRPC,
				Metadata: MessageMetadata{
					StreamID:    h2msg.StreamID,
					IsEndStream: h2msg.IsEndStream,
					IsRequest:   grpcMsg.IsRequest,
					Service:     grpcMsg.ServiceName,
					Method:      grpcMsg.MethodName,
				},
			})
			stream.MessageCount++

			// Handle remaining data in body
			if bytesRead < len(h2msg.Body) {
				// Multiple gRPC messages in one HTTP/2 DATA frame
				// This is common in streaming scenarios
				// TODO: Handle multiple gRPC messages
			}
		} else {
			// HEADERS-only frame
			data := serializeHTTP2Message(h2msg)
			messages = append(messages, Message{
				Data:     data,
				Protocol: events.ProtoGRPC,
				Metadata: MessageMetadata{
					StreamID:    h2msg.StreamID,
					IsEndStream: h2msg.IsEndStream,
					IsRequest:   h2msg.IsRequest,
					Method:      h2msg.Method,
				},
			})
			stream.MessageCount++
		}
	}

	return messages, nil
}

// serializeHTTP2Message converts HTTP/2 message to readable format
func serializeHTTP2Message(msg *http2.Message) []byte {
	var buf bytes.Buffer

	if msg.IsRequest {
		buf.WriteString(fmt.Sprintf("%s %s HTTP/2.0\r\n", msg.Method, msg.Path))
	} else {
		buf.WriteString(fmt.Sprintf("HTTP/2.0 %s\r\n", msg.Status))
	}

	for k, v := range msg.Headers {
		if !strings.HasPrefix(k, ":") {
			buf.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
		}
	}

	buf.WriteString("\r\n")
	buf.Write(msg.Body)

	return buf.Bytes()
}

// serializeGRPCMessage converts gRPC message to readable format
func serializeGRPCMessage(grpcMsg *grpc.Message, h2msg *http2.Message) []byte {
	var buf bytes.Buffer

	if grpcMsg.IsRequest {
		buf.WriteString(fmt.Sprintf("POST /%s/%s HTTP/2.0\r\n",
			grpcMsg.ServiceName, grpcMsg.MethodName))
	} else {
		buf.WriteString(fmt.Sprintf("HTTP/2.0 %s\r\n", h2msg.Status))
	}

	buf.WriteString("content-type: application/grpc\r\n")

	for k, v := range grpcMsg.Headers {
		if !strings.HasPrefix(k, ":") {
			buf.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
		}
	}

	buf.WriteString(fmt.Sprintf("\r\n[gRPC %s: %d bytes, compressed=%v]",
		grpcMsg.MethodName, grpcMsg.MessageLength, grpcMsg.Compressed))

	return buf.Bytes()
}

// Helper functions
func getContentLength(headers []byte) int {
	clPrefix := []byte("Content-Length: ")
	idx := bytes.Index(headers, clPrefix)
	if idx == -1 {
		return 0
	}

	start := idx + len(clPrefix)
	end := bytes.Index(headers[start:], []byte("\r\n"))
	if end == -1 {
		return 0
	}

	lenStr := string(headers[start : start+end])
	var length int
	fmt.Sscanf(lenStr, "%d", &length)
	return length
}

func isChunkedEncoding(headers []byte) bool {
	return bytes.Contains(headers, []byte("Transfer-Encoding: chunked"))
}

func findChunkedEnd(buf []byte) int {
	endMarker := []byte("0\r\n\r\n")
	idx := bytes.Index(buf, endMarker)
	if idx == -1 {
		return -1
	}
	return idx + len(endMarker)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// cleanupLoop periodically removes stale streams
func (r *Reassembler) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Second) // More frequent cleanup
	defer ticker.Stop()

	for range ticker.C {
		r.mu.Lock()
		now := time.Now()
		cleaned := 0

		for key, stream := range r.streams {
			// More aggressive timeout for idle streams
			idleTime := now.Sub(stream.LastSeen)

			// If stream has extracted messages but been idle > 10s, clean it
			if stream.MessageCount > 0 && idleTime > 10*time.Second {
				delete(r.streams, key)
				cleaned++
				continue
			}

			// If stream never extracted messages and idle > 30s, clean it
			if stream.MessageCount == 0 && idleTime > r.timeout {
				delete(r.streams, key)
				cleaned++
			}
		}

		r.statsMu.Lock()
		r.stats.ActiveStreams = uint64(len(r.streams))
		r.statsMu.Unlock()
		r.mu.Unlock()

		if cleaned > 0 {
			slog.Debug("Cleaned up stale streams", "count", cleaned, "remaining", len(r.streams))
		}
	}
}

// statsLoop periodically logs statistics
func (r *Reassembler) statsLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		stats := r.GetStats()
		slog.Info("Reassembler statistics",
			"active_streams", stats.ActiveStreams,
			"total_streams", stats.TotalStreams,
			"completed_messages", stats.CompletedMessages,
			"dropped_messages", stats.DroppedMessages,
			"bytes_processed", stats.BytesProcessed,
			"parse_errors", stats.ParseErrors)
	}
}

// GetActiveStreams returns the number of active streams
func (r *Reassembler) GetActiveStreams() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.streams)
}

// GetStats returns current statistics
func (r *Reassembler) GetStats() ReassemblerStats {
	r.statsMu.RLock()
	defer r.statsMu.RUnlock()
	return r.stats
}

// Reset clears all stream state
func (r *Reassembler) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.streams = make(map[StreamKey]*Stream)
	r.statsMu.Lock()
	r.stats = ReassemblerStats{}
	r.statsMu.Unlock()
}

// func strings.HasPrefix(s, prefix string) bool {
// 	return len(s) >= len(prefix) && s[0:len(prefix)] == prefix
// }
