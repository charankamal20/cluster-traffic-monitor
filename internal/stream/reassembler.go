package stream

import (
	"bytes"
	"fmt"
	"sync"
	"time"
)

// StreamKey uniquely identifies a TCP stream
type StreamKey struct {
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
}

// Stream represents an ongoing TCP stream
type Stream struct {
	Key       StreamKey
	Buffer    *bytes.Buffer
	LastSeen  time.Time
	Direction uint8 // 0=egress, 1=ingress
}

// Reassembler assembles TCP streams from chunks
type Reassembler struct {
	streams map[StreamKey]*Stream
	mu      sync.RWMutex
	timeout time.Duration
}

// NewReassembler creates a new stream reassembler
func NewReassembler(timeout time.Duration) *Reassembler {
	r := &Reassembler{
		streams: make(map[StreamKey]*Stream),
		timeout: timeout,
	}
	go r.cleanupLoop()
	return r
}

// AddChunk adds data to the stream and returns complete messages
func (r *Reassembler) AddChunk(key StreamKey, data []byte, direction uint8) [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()

	stream, exists := r.streams[key]
	if !exists {
		stream = &Stream{
			Key:       key,
			Buffer:    bytes.NewBuffer(nil),
			Direction: direction,
		}
		r.streams[key] = stream
	}

	// Append new data
	stream.Buffer.Write(data)
	stream.LastSeen = time.Now()

	// Try to extract complete messages
	return r.extractMessages(stream)
}

// extractMessages finds complete HTTP messages in buffer
func (r *Reassembler) extractMessages(stream *Stream) [][]byte {
	var messages [][]byte

	for {
		// Look for HTTP message boundary
		buf := stream.Buffer.Bytes()

		if stream.Direction == 0 { // Egress (request)
			// Look for "\r\n\r\n" (end of headers)
			idx := bytes.Index(buf, []byte("\r\n\r\n"))
			if idx == -1 {
				break // Incomplete headers
			}

			// Check if we have body
			headerEnd := idx + 4
			bodyLen := getContentLength(buf[:headerEnd])

			if bodyLen > 0 {
				totalLen := headerEnd + bodyLen
				if len(buf) < totalLen {
					break // Incomplete body
				}

				// Extract complete request
				msg := make([]byte, totalLen)
				copy(msg, buf[:totalLen])
				messages = append(messages, msg)

				// Remove from buffer
				stream.Buffer = bytes.NewBuffer(buf[totalLen:])
			} else {
				// No body, just headers
				msg := make([]byte, headerEnd)
				copy(msg, buf[:headerEnd])
				messages = append(messages, msg)
				stream.Buffer = bytes.NewBuffer(buf[headerEnd:])
			}

		} else { // Ingress (response)
			// Similar logic for HTTP responses
			idx := bytes.Index(buf, []byte("\r\n\r\n"))
			if idx == -1 {
				break
			}

			headerEnd := idx + 4
			bodyLen := getContentLength(buf[:headerEnd])

			// Handle chunked encoding
			if isChunkedEncoding(buf[:headerEnd]) {
				completeLen := findChunkedEnd(buf)
				if completeLen == -1 {
					break // Incomplete chunked body
				}
				msg := make([]byte, completeLen)
				copy(msg, buf[:completeLen])
				messages = append(messages, msg)
				stream.Buffer = bytes.NewBuffer(buf[completeLen:])
			} else if bodyLen > 0 {
				totalLen := headerEnd + bodyLen
				if len(buf) < totalLen {
					break
				}
				msg := make([]byte, totalLen)
				copy(msg, buf[:totalLen])
				messages = append(messages, msg)
				stream.Buffer = bytes.NewBuffer(buf[totalLen:])
			} else {
				msg := make([]byte, headerEnd)
				copy(msg, buf[:headerEnd])
				messages = append(messages, msg)
				stream.Buffer = bytes.NewBuffer(buf[headerEnd:])
			}
		}
	}

	return messages
}

// getContentLength parses Content-Length header
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

// isChunkedEncoding checks for chunked transfer encoding
func isChunkedEncoding(headers []byte) bool {
	return bytes.Contains(headers, []byte("Transfer-Encoding: chunked"))
}

// findChunkedEnd finds the end of chunked encoding
func findChunkedEnd(buf []byte) int {
	// Look for "0\r\n\r\n" (end of chunked encoding)
	endMarker := []byte("0\r\n\r\n")
	idx := bytes.Index(buf, endMarker)
	if idx == -1 {
		return -1
	}
	return idx + len(endMarker)
}

// cleanupLoop periodically removes stale streams
func (r *Reassembler) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		r.mu.Lock()
		now := time.Now()
		for key, stream := range r.streams {
			if now.Sub(stream.LastSeen) > r.timeout {
				delete(r.streams, key)
			}
		}
		r.mu.Unlock()
	}
}

// GetActiveStreams returns the number of active streams
func (r *Reassembler) GetActiveStreams() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.streams)
}
