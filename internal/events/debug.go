package events

import (
	"encoding/binary"
	"fmt"
	"time"
)

// DebugEvent for minimal debugging
type DebugEvent struct {
	Timestamp uint64
	PID       uint32
	DstPort   uint16
	IterType  uint8
	Count     uint32
}

// ParseDebugEvent parses raw bytes into a DebugEvent
func ParseDebugEvent(data []byte) (*DebugEvent, error) {
	if len(data) < 19 {
		return nil, fmt.Errorf("data too short: %d bytes", len(data))
	}

	event := &DebugEvent{}
	event.Timestamp = binary.LittleEndian.Uint64(data[0:8])
	event.PID = binary.LittleEndian.Uint32(data[8:12])
	event.DstPort = binary.LittleEndian.Uint16(data[12:14])
	event.IterType = data[14]
	event.Count = binary.LittleEndian.Uint32(data[15:19])

	return event, nil
}

// String returns formatted debug output
func (e *DebugEvent) String() string {
	return fmt.Sprintf("[%s] PID:%d Port:%d IterType:%d Count:%d",
		time.Unix(0, int64(e.Timestamp)).Format("15:04:05.000"),
		e.PID, e.DstPort, e.IterType, e.Count)
}
