package events

import (
	"encoding/binary"
	"fmt"
	"time"
)

// Protocol types
const (
	ProtoUnknown = 0
	ProtoHTTP1   = 1
	ProtoHTTP2   = 2
	ProtoGRPC    = 3
)

// DataEvent represents a raw TCP data chunk from eBPF
type DataEvent struct {
	Timestamp uint64
	PID       uint32
	TID       uint32
	SrcIP     uint32
	DstIP     uint32
	SrcPort   uint16
	DstPort   uint16
	DataLen   uint32
	Direction uint8
	Protocol  uint8   // NEW: protocol type
	_         [6]byte // padding
	SockPtr   uint64
	Payload   []byte
}

// ParseDataEvent parses raw bytes into a DataEvent
func ParseDataEvent(data []byte) (*DataEvent, error) {
	const headerSize = 48
	if len(data) < headerSize {
		return nil, fmt.Errorf("data too short: %d bytes, need at least %d", len(data), headerSize)
	}

	event := &DataEvent{}
	event.Timestamp = binary.LittleEndian.Uint64(data[0:8])
	event.PID = binary.LittleEndian.Uint32(data[8:12])
	event.TID = binary.LittleEndian.Uint32(data[12:16])
	event.SrcIP = binary.LittleEndian.Uint32(data[16:20])
	event.DstIP = binary.LittleEndian.Uint32(data[20:24])
	event.SrcPort = binary.LittleEndian.Uint16(data[24:26])
	event.DstPort = binary.LittleEndian.Uint16(data[26:28])
	event.DataLen = binary.LittleEndian.Uint32(data[28:32])
	event.Direction = data[32]
	event.Protocol = data[33] // NEW
	// Skip _pad[6] at bytes 34-40
	event.SockPtr = binary.LittleEndian.Uint64(data[40:48])

	if len(data) > headerSize {
		if uint32(len(data)-headerSize) < event.DataLen {
			event.DataLen = uint32(len(data) - headerSize)
		}
		event.Payload = make([]byte, event.DataLen)
		copy(event.Payload, data[headerSize:headerSize+int(event.DataLen)])
	}

	return event, nil
}

func (e *DataEvent) SrcIPString() string {
	return intToIP(e.SrcIP).String()
}

func (e *DataEvent) DstIPString() string {
	return intToIP(e.DstIP).String()
}

func (e *DataEvent) Time() time.Time {
	return time.Unix(0, int64(e.Timestamp))
}

func (e *DataEvent) ProtocolString() string {
	switch e.Protocol {
	case ProtoHTTP1:
		return "HTTP/1.x"
	case ProtoHTTP2:
		return "HTTP/2"
	case ProtoGRPC:
		return "gRPC"
	default:
		return "Unknown"
	}
}
