package events

import (
	"encoding/binary"
	"fmt"
	"time"
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
	Direction uint8 // 0=Egress, 1=Ingress
	SockPtr   uint64 // ⭐ ADDED
	Payload   []byte
}

// ParseDataEvent parses raw bytes into a DataEvent
func ParseDataEvent(data []byte) (*DataEvent, error) {
	// Struct layout (with sock_ptr):
	// timestamp: 0-8
	// pid: 8-12
	// tid: 12-16
	// src_ip: 16-20
	// dst_ip: 20-24
	// src_port: 24-26
	// dst_port: 26-28
	// data_len: 28-32
	// direction: 32-33
	// _pad[7]: 33-40
	// sock_ptr: 40-48  ⭐ ADDED
	// payload: 48-...  ⭐ MOVED FROM 33

	const headerSize = 48 // ⭐ CHANGED FROM 33

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
	// Skip _pad[7] at bytes 33-40
	event.SockPtr = binary.LittleEndian.Uint64(data[40:48]) // ⭐ ADDED

	// Read payload
	if len(data) > headerSize {
		// Cap validation
		if uint32(len(data)-headerSize) < event.DataLen {
			// This might happen if buffer was truncated
			event.DataLen = uint32(len(data) - headerSize)
		}

		event.Payload = make([]byte, event.DataLen)
		copy(event.Payload, data[headerSize:headerSize+int(event.DataLen)])
	}

	return event, nil
}

// Helper methods
func (e *DataEvent) SrcIPString() string {
	return intToIP(e.SrcIP).String()
}

func (e *DataEvent) DstIPString() string {
	return intToIP(e.DstIP).String()
}

func (e *DataEvent) Time() time.Time {
	return time.Unix(0, int64(e.Timestamp))
}

