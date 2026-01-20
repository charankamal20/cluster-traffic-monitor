package grpc

import (
	"encoding/binary"
	"fmt"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
)

const (
	// gRPC compression flags
	CompressionNone = 0x00
	CompressionGzip = 0x01

	// gRPC message format:
	// Compressed-Flag (1 byte) | Message-Length (4 bytes) | Message (variable)
	GRPCHeaderSize = 5
)

// Message represents a parsed gRPC message
type Message struct {
	ServiceName   string
	MethodName    string
	IsRequest     bool
	Compressed    bool
	MessageLength uint32
	RawMessage    []byte
	Headers       map[string]string
	Trailers      map[string]string
	Status        string
	StatusCode    int32
	StatusMessage string
}

// Parser handles gRPC message parsing
type Parser struct {
	// Store service definitions if available
	serviceRegistry map[string]*ServiceDefinition
}

// ServiceDefinition holds metadata about a gRPC service
type ServiceDefinition struct {
	Name    string
	Methods map[string]*MethodDefinition
}

// MethodDefinition holds metadata about a gRPC method
type MethodDefinition struct {
	Name         string
	InputType    string
	OutputType   string
	ClientStream bool
	ServerStream bool
}

// NewParser creates a new gRPC parser
func NewParser() *Parser {
	return &Parser{
		serviceRegistry: make(map[string]*ServiceDefinition),
	}
}

// ParseMessage parses a gRPC message from the wire format
func (p *Parser) ParseMessage(data []byte, headers map[string]string) (*Message, int, error) {
	if len(data) < GRPCHeaderSize {
		return nil, 0, fmt.Errorf("insufficient data for gRPC header: got %d bytes, need %d", len(data), GRPCHeaderSize)
	}

	msg := &Message{
		Headers: headers,
	}

	// Extract service and method from :path header
	// Format: /package.Service/Method
	if path, ok := headers[":path"]; ok {
		parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
		if len(parts) == 2 {
			msg.ServiceName = parts[0]
			msg.MethodName = parts[1]
		}
	}

	// Determine if request or response based on :method header
	if method, ok := headers[":method"]; ok {
		msg.IsRequest = method == "POST"
	}

	// Parse gRPC message header
	compressionFlag := data[0]
	msg.Compressed = compressionFlag != CompressionNone
	msg.MessageLength = binary.BigEndian.Uint32(data[1:5])

	// Validate message length
	if int(msg.MessageLength) > len(data)-GRPCHeaderSize {
		return nil, 0, fmt.Errorf("incomplete gRPC message: declared length %d, available %d",
			msg.MessageLength, len(data)-GRPCHeaderSize)
	}

	// Extract message payload
	messageEnd := GRPCHeaderSize + int(msg.MessageLength)
	msg.RawMessage = make([]byte, msg.MessageLength)
	copy(msg.RawMessage, data[GRPCHeaderSize:messageEnd])

	return msg, messageEnd, nil
}

// ParseTrailers extracts gRPC trailers (status information)
func (p *Parser) ParseTrailers(headers map[string]string) {
	// gRPC trailers are sent as HTTP/2 trailers
	// Common trailer headers:
	// - grpc-status: Status code (0 = OK)
	// - grpc-message: Status message
	// - grpc-status-details-bin: Detailed error info (protobuf encoded)
}

// DecodeProtobuf attempts to decode a protobuf message
// This is best-effort without schema information
func (p *Parser) DecodeProtobuf(data []byte) (map[string]interface{}, error) {
	if len(data) == 0 {
		return nil, nil
	}

	fields := make(map[string]interface{})
	offset := 0

	for offset < len(data) {
		// Read field tag and wire type
		tag, wireType, n := protowire.ConsumeTag(data[offset:])
		if n < 0 {
			break
		}
		offset += n

		fieldNum := uint32(tag >> 3)

		// Parse based on wire type
		switch wireType {
		case protowire.VarintType:
			// Varint (int32, int64, uint32, uint64, bool, enum)
			val, n := protowire.ConsumeVarint(data[offset:])
			if n < 0 {
				return fields, fmt.Errorf("failed to parse varint at offset %d", offset)
			}
			fields[fmt.Sprintf("field_%d", fieldNum)] = val
			offset += n

		case protowire.Fixed64Type:
			// Fixed64 (fixed64, sfixed64, double)
			val, n := protowire.ConsumeFixed64(data[offset:])
			if n < 0 {
				return fields, fmt.Errorf("failed to parse fixed64 at offset %d", offset)
			}
			fields[fmt.Sprintf("field_%d", fieldNum)] = val
			offset += n

		case protowire.BytesType:
			// Length-delimited (string, bytes, embedded messages, repeated fields)
			val, n := protowire.ConsumeBytes(data[offset:])
			if n < 0 {
				return fields, fmt.Errorf("failed to parse bytes at offset %d", offset)
			}
			// Try to interpret as string
			if isPrintableASCII(val) {
				fields[fmt.Sprintf("field_%d", fieldNum)] = string(val)
			} else {
				// Try to recursively decode as nested message
				nested, err := p.DecodeProtobuf(val)
				if err == nil && len(nested) > 0 {
					fields[fmt.Sprintf("field_%d", fieldNum)] = nested
				} else {
					fields[fmt.Sprintf("field_%d_bytes", fieldNum)] = fmt.Sprintf("<%d bytes>", len(val))
				}
			}
			offset += n

		case protowire.Fixed32Type:
			// Fixed32 (fixed32, sfixed32, float)
			val, n := protowire.ConsumeFixed32(data[offset:])
			if n < 0 {
				return fields, fmt.Errorf("failed to parse fixed32 at offset %d", offset)
			}
			fields[fmt.Sprintf("field_%d", fieldNum)] = val
			offset += n

		default:
			// Unknown wire type, skip
			return fields, fmt.Errorf("unknown wire type %d at offset %d", wireType, offset)
		}
	}

	return fields, nil
}

// isPrintableASCII checks if bytes are printable ASCII
func isPrintableASCII(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	for _, b := range data {
		if b < 32 || b > 126 {
			return false
		}
	}
	return true
}

// ExtractGRPCMetadata extracts gRPC-specific metadata from headers
func ExtractGRPCMetadata(headers map[string]string) (timeout string, encoding string, metadata map[string]string) {
	metadata = make(map[string]string)

	for k, v := range headers {
		switch k {
		case "grpc-timeout":
			timeout = v
		case "grpc-encoding":
			encoding = v
		case "content-type":
			// Skip, already processed
		case ":method", ":scheme", ":path", ":authority", ":status":
			// Skip pseudo-headers
		default:
			// Custom metadata
			if strings.HasPrefix(k, "grpc-") || !strings.HasPrefix(k, ":") {
				metadata[k] = v
			}
		}
	}

	return
}

// FormatGRPCMessage formats a gRPC message for logging
func (m *Message) FormatForLogging() string {
	direction := "request"
	if !m.IsRequest {
		direction = "response"
	}

	return fmt.Sprintf("gRPC %s: %s/%s (compressed=%v, size=%d bytes)",
		direction, m.ServiceName, m.MethodName, m.Compressed, m.MessageLength)
}

// IsComplete checks if message is complete
func (m *Message) IsComplete() bool {
	return len(m.RawMessage) == int(m.MessageLength)
}
