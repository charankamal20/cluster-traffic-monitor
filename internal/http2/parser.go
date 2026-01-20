package http2

import (
	"encoding/binary"
	"fmt"
	"sync"
)

const (
	// Frame types
	FrameData         = 0x0
	FrameHeaders      = 0x1
	FramePriority     = 0x2
	FrameRSTStream    = 0x3
	FrameSettings     = 0x4
	FramePushPromise  = 0x5
	FramePing         = 0x6
	FrameGoAway       = 0x7
	FrameWindowUpdate = 0x8
	FrameContinuation = 0x9

	// Frame flags
	FlagDataEndStream     = 0x1
	FlagDataPadded        = 0x8
	FlagHeadersEndStream  = 0x1
	FlagHeadersEndHeaders = 0x4
	FlagHeadersPadded     = 0x8
	FlagHeadersPriority   = 0x20
	FlagSettingsAck       = 0x1
	FlagPingAck           = 0x1

	// Settings
	SettingsHeaderTableSize      = 0x1
	SettingsEnablePush           = 0x2
	SettingsMaxConcurrentStreams = 0x3
	SettingsInitialWindowSize    = 0x4
	SettingsMaxFrameSize         = 0x5
	SettingsMaxHeaderListSize    = 0x6

	// HTTP/2 Connection Preface
	ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

	// Limits
	MaxFrameSize        = 16777215 // 2^24 - 1
	DefaultWindowSize   = 65535
	DefaultMaxFrameSize = 16384
)

// FrameHeader represents the 9-byte HTTP/2 frame header
type FrameHeader struct {
	Length   uint32 // 24-bit
	Type     uint8
	Flags    uint8
	StreamID uint32 // 31-bit
}

// Frame represents a complete HTTP/2 frame
type Frame struct {
	Header  FrameHeader
	Payload []byte
}

// Message represents a reconstructed HTTP request or response
type Message struct {
	StreamID    uint32
	IsRequest   bool
	Method      string
	Path        string
	Scheme      string
	Authority   string
	Status      string
	Headers     map[string]string
	Body        []byte
	Trailers    map[string]string
	ContentType string
	IsEndStream bool
	Priority    int32
}

// StreamState tracks the state of an HTTP/2 stream
type StreamState struct {
	StreamID      uint32
	Message       *Message
	HeadersBuffer []byte // Buffer for CONTINUATION frames
	IsComplete    bool
}

// Parser handles HTTP/2 frame parsing and stream reconstruction
type Parser struct {
	hpackDecoder      *HPACKDecoder
	streams           map[uint32]*StreamState
	mu                sync.RWMutex
	maxFrameSize      uint32
	maxHeaderSize     uint32
	connectionPreface bool
}

// NewParser creates a new HTTP/2 parser
func NewParser() *Parser {
	return &Parser{
		hpackDecoder:      NewHPACKDecoder(4096),
		streams:           make(map[uint32]*StreamState),
		maxFrameSize:      DefaultMaxFrameSize,
		maxHeaderSize:     16384, // Common default
		connectionPreface: false,
	}
}

// ParseFrameHeader parses the 9-byte frame header
func ParseFrameHeader(data []byte) (*FrameHeader, error) {
	if len(data) < 9 {
		return nil, fmt.Errorf("insufficient data for frame header: got %d bytes, need 9", len(data))
	}

	fh := &FrameHeader{}

	// Length is 24-bit big-endian
	fh.Length = uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])

	fh.Type = data[3]
	fh.Flags = data[4]

	// Stream ID is 31-bit (ignore reserved bit)
	fh.StreamID = binary.BigEndian.Uint32(data[5:9]) & 0x7FFFFFFF

	// Validate frame length
	if fh.Length > MaxFrameSize {
		return nil, fmt.Errorf("frame too large: %d bytes (max %d)", fh.Length, MaxFrameSize)
	}

	// Validate frame type
	if fh.Type > FrameContinuation {
		return nil, fmt.Errorf("unknown frame type: %d", fh.Type)
	}

	// Validate stream ID per frame type
	if err := fh.ValidateStreamID(); err != nil {
		return nil, err
	}

	return fh, nil
}

// ValidateStreamID validates stream ID based on frame type
func (fh *FrameHeader) ValidateStreamID() error {
	switch fh.Type {
	case FrameSettings, FramePing, FrameGoAway:
		if fh.StreamID != 0 {
			return fmt.Errorf("frame type %d must use stream 0, got %d", fh.Type, fh.StreamID)
		}
	case FrameData, FrameHeaders, FramePriority, FrameRSTStream, FramePushPromise, FrameContinuation:
		if fh.StreamID == 0 {
			return fmt.Errorf("frame type %d must use stream > 0, got 0", fh.Type)
		}
	}
	return nil
}

// IsEndStream returns true if this frame has END_STREAM flag
func (fh *FrameHeader) IsEndStream() bool {
	return (fh.Flags & FlagDataEndStream) != 0
}

// IsEndHeaders returns true if this frame has END_HEADERS flag
func (fh *FrameHeader) IsEndHeaders() bool {
	return (fh.Flags & FlagHeadersEndHeaders) != 0
}

// ParseFrames parses HTTP/2 frames from a byte buffer
func (p *Parser) ParseFrames(data []byte) ([]*Message, []byte, error) {
	var messages []*Message
	offset := 0

	// Check for HTTP/2 connection preface at the start
	if !p.connectionPreface && len(data) >= len(ClientPreface) {
		if string(data[:len(ClientPreface)]) == ClientPreface {
			p.connectionPreface = true
			offset = len(ClientPreface)
		}
	}

	for offset+9 <= len(data) {
		// Parse frame header
		fh, err := ParseFrameHeader(data[offset:])
		if err != nil {
			return messages, data[offset:], fmt.Errorf("parse frame header: %w", err)
		}

		frameEnd := offset + 9 + int(fh.Length)
		if frameEnd > len(data) {
			// Incomplete frame, return remaining data
			return messages, data[offset:], nil
		}

		payload := data[offset+9 : frameEnd]

		// Process frame based on type
		msg, err := p.processFrame(fh, payload)
		if err != nil {
			// Log error but continue processing
			offset = frameEnd
			continue
		}

		if msg != nil {
			messages = append(messages, msg)
		}

		offset = frameEnd
	}

	return messages, data[offset:], nil
}

// processFrame processes a single frame and returns a message if complete
func (p *Parser) processFrame(fh *FrameHeader, payload []byte) (*Message, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	switch fh.Type {
	case FrameSettings:
		return nil, p.handleSettings(fh, payload)

	case FrameHeaders:
		return p.handleHeaders(fh, payload)

	case FrameData:
		return p.handleData(fh, payload)

	case FrameContinuation:
		return p.handleContinuation(fh, payload)

	case FrameRSTStream:
		return p.handleRSTStream(fh, payload)

	case FramePing, FrameWindowUpdate:
		// Control frames, no message content
		return nil, nil

	default:
		// Unknown frame type, skip
		return nil, nil
	}
}

// handleSettings processes SETTINGS frame
func (p *Parser) handleSettings(fh *FrameHeader, payload []byte) error {
	if fh.Flags&FlagSettingsAck != 0 {
		// ACK frame, no payload
		return nil
	}

	if len(payload)%6 != 0 {
		return fmt.Errorf("invalid SETTINGS frame payload length: %d", len(payload))
	}

	for i := 0; i < len(payload); i += 6 {
		id := binary.BigEndian.Uint16(payload[i : i+2])
		value := binary.BigEndian.Uint32(payload[i+2 : i+6])

		switch id {
		case SettingsHeaderTableSize:
			p.hpackDecoder.SetMaxDynamicTableSize(value)
		case SettingsMaxFrameSize:
			if value < 16384 || value > 16777215 {
				return fmt.Errorf("invalid SETTINGS_MAX_FRAME_SIZE: %d", value)
			}
			p.maxFrameSize = value
		case SettingsMaxHeaderListSize:
			p.maxHeaderSize = value
		}
	}

	return nil
}

// handleHeaders processes HEADERS frame
func (p *Parser) handleHeaders(fh *FrameHeader, payload []byte) (*Message, error) {
	// Parse padding if present
	padLen := uint8(0)
	if fh.Flags&FlagHeadersPadded != 0 {
		if len(payload) == 0 {
			return nil, fmt.Errorf("HEADERS frame with PADDED flag but no payload")
		}
		padLen = payload[0]
		payload = payload[1:]
	}

	// Skip priority if present
	if fh.Flags&FlagHeadersPriority != 0 {
		if len(payload) < 5 {
			return nil, fmt.Errorf("HEADERS frame with PRIORITY flag but insufficient data")
		}
		payload = payload[5:]
	}

	// Remove padding
	if int(padLen) >= len(payload) {
		return nil, fmt.Errorf("padding length %d exceeds payload length %d", padLen, len(payload))
	}
	if padLen > 0 {
		payload = payload[:len(payload)-int(padLen)]
	}

	// Get or create stream state
	stream, ok := p.streams[fh.StreamID]
	if !ok {
		stream = &StreamState{
			StreamID: fh.StreamID,
			Message: &Message{
				StreamID: fh.StreamID,
				Headers:  make(map[string]string),
			},
		}
		p.streams[fh.StreamID] = stream
	}

	// Accumulate headers if CONTINUATION frames expected
	if fh.Flags&FlagHeadersEndHeaders == 0 {
		stream.HeadersBuffer = append(stream.HeadersBuffer, payload...)
		return nil, nil // Wait for CONTINUATION frames
	}

	// Decode HPACK
	headerData := payload
	if len(stream.HeadersBuffer) > 0 {
		headerData = append(stream.HeadersBuffer, payload...)
		stream.HeadersBuffer = nil
	}

	headers, err := p.hpackDecoder.DecodeHeaders(headerData)
	if err != nil {
		delete(p.streams, fh.StreamID)
		return nil, fmt.Errorf("HPACK decode error: %w", err)
	}

	// Extract pseudo-headers and regular headers
	method, path, scheme, authority, status := ExtractPseudoHeaders(headers)
	stream.Message.Method = method
	stream.Message.Path = path
	stream.Message.Scheme = scheme
	stream.Message.Authority = authority
	stream.Message.Status = status
	stream.Message.IsRequest = method != ""
	stream.Message.Headers = HeadersToMap(headers)

	// Extract content-type
	if ct, ok := stream.Message.Headers["content-type"]; ok {
		stream.Message.ContentType = ct
	}

	// Check if stream is complete
	if fh.IsEndStream() {
		stream.Message.IsEndStream = true
		stream.IsComplete = true
		delete(p.streams, fh.StreamID)
		return stream.Message, nil
	}

	return nil, nil
}

// handleData processes DATA frame
func (p *Parser) handleData(fh *FrameHeader, payload []byte) (*Message, error) {
	// Parse padding if present
	padLen := uint8(0)
	if fh.Flags&FlagDataPadded != 0 {
		if len(payload) == 0 {
			return nil, fmt.Errorf("DATA frame with PADDED flag but no payload")
		}
		padLen = payload[0]
		payload = payload[1:]
	}

	// Remove padding
	if int(padLen) >= len(payload) {
		return nil, fmt.Errorf("padding length %d exceeds payload length %d", padLen, len(payload))
	}
	if padLen > 0 {
		payload = payload[:len(payload)-int(padLen)]
	}

	stream, ok := p.streams[fh.StreamID]
	if !ok {
		// Stream might have been closed or not started yet
		// For now, ignore data for unknown streams
		return nil, nil
	}

	stream.Message.Body = append(stream.Message.Body, payload...)

	if fh.IsEndStream() {
		stream.Message.IsEndStream = true
		stream.IsComplete = true
		delete(p.streams, fh.StreamID)
		return stream.Message, nil
	}

	return nil, nil
}

// handleContinuation processes CONTINUATION frame
func (p *Parser) handleContinuation(fh *FrameHeader, payload []byte) (*Message, error) {
	stream, ok := p.streams[fh.StreamID]
	if !ok {
		return nil, fmt.Errorf("CONTINUATION frame for unknown stream %d", fh.StreamID)
	}

	stream.HeadersBuffer = append(stream.HeadersBuffer, payload...)

	if fh.Flags&FlagHeadersEndHeaders != 0 {
		// End of headers, decode now
		headers, err := p.hpackDecoder.DecodeHeaders(stream.HeadersBuffer)
		if err != nil {
			delete(p.streams, fh.StreamID)
			return nil, fmt.Errorf("HPACK decode error: %w", err)
		}
		stream.HeadersBuffer = nil

		// Update message headers
		currentHeaders := HeadersToMap(headers)
		for k, v := range currentHeaders {
			stream.Message.Headers[k] = v
		}

		// Extract content-type again if present
		if ct, ok := stream.Message.Headers["content-type"]; ok {
			stream.Message.ContentType = ct
		}

		if fh.IsEndStream() {
			stream.Message.IsEndStream = true
			stream.IsComplete = true
			delete(p.streams, fh.StreamID)
			return stream.Message, nil
		}
	}

	return nil, nil
}

// handleRSTStream processes RST_STREAM frame
func (p *Parser) handleRSTStream(fh *FrameHeader, payload []byte) (*Message, error) {
	if len(payload) != 4 {
		return nil, fmt.Errorf("invalid RST_STREAM payload length: %d", len(payload))
	}

	errorCode := binary.BigEndian.Uint32(payload)
	_ = errorCode // Ignore for now

	delete(p.streams, fh.StreamID)
	return nil, nil
}

// IsHTTP2Preface checks if data starts with HTTP/2 connection preface
func IsHTTP2Preface(data []byte) bool {
	if len(data) < len(ClientPreface) {
		return false
	}
	return string(data[:len(ClientPreface)]) == ClientPreface
}
