package events

import (
    "encoding/binary"
    "fmt"
    "net"
    "time"
)

// HTTPEvent represents an HTTP event captured by eBPF
// Must match the C struct layout exactly
type HTTPEvent struct {
    Timestamp   uint64
    PID         uint32
    TID         uint32
    SrcIP       uint32
    DstIP       uint32
    SrcPort     uint16
    DstPort     uint16
    Method      [8]byte
    Path        [128]byte
    Host        [64]byte
    PayloadSize uint32
    IsRequest   uint8
    _           [3]byte // Padding for alignment
}

// ParseEvent parses raw bytes into an HTTPEvent
func ParseEvent(data []byte) (*HTTPEvent, error) {
    if len(data) < 256 {
        return nil, fmt.Errorf("data too short: %d bytes", len(data))
    }
    
    event := &HTTPEvent{}
    event.Timestamp = binary.LittleEndian.Uint64(data[0:8])
    event.PID = binary.LittleEndian.Uint32(data[8:12])
    event.TID = binary.LittleEndian.Uint32(data[12:16])
    event.SrcIP = binary.LittleEndian.Uint32(data[16:20])
    event.DstIP = binary.LittleEndian.Uint32(data[20:24])
    event.SrcPort = binary.LittleEndian.Uint16(data[24:26])
    event.DstPort = binary.LittleEndian.Uint16(data[26:28])
    copy(event.Method[:], data[28:36])
    copy(event.Path[:], data[36:164])
    copy(event.Host[:], data[164:228])
    event.PayloadSize = binary.LittleEndian.Uint32(data[228:232])
    event.IsRequest = data[232]
    
    return event, nil
}

// MethodString returns the HTTP method as a string
func (e *HTTPEvent) MethodString() string {
    return cString(e.Method[:])
}

// PathString returns the HTTP path as a string
func (e *HTTPEvent) PathString() string {
    return cString(e.Path[:])
}

// HostString returns the HTTP host as a string
func (e *HTTPEvent) HostString() string {
    return cString(e.Host[:])
}

// SrcIPString returns source IP as string
func (e *HTTPEvent) SrcIPString() string {
    return intToIP(e.SrcIP).String()
}

// DstIPString returns destination IP as string
func (e *HTTPEvent) DstIPString() string {
    return intToIP(e.DstIP).String()
}

// Time returns the timestamp as time.Time
func (e *HTTPEvent) Time() time.Time {
    return time.Unix(0, int64(e.Timestamp))
}

// String returns a formatted string representation
func (e *HTTPEvent) String() string {
    if e.IsRequest == 1 {
        return fmt.Sprintf("[%s] %s:%d -> %s:%d | %s %s | Host: %s | Size: %d bytes",
            e.Time().Format("15:04:05.000"),
            e.SrcIPString(), e.SrcPort,
            e.DstIPString(), e.DstPort,
            e.MethodString(), e.PathString(),
            e.HostString(), e.PayloadSize)
    }
    return fmt.Sprintf("[%s] %s:%d <- %s:%d | HTTP Response | Size: %d bytes",
        e.Time().Format("15:04:05.000"),
        e.DstIPString(), e.DstPort,
        e.SrcIPString(), e.SrcPort,
        e.PayloadSize)
}

// Helper to convert null-terminated C string to Go string
func cString(b []byte) string {
    for i, v := range b {
        if v == 0 {
            return string(b[:i])
        }
    }
    return string(b)
}

// Helper to convert uint32 IP to net.IP
func intToIP(ip uint32) net.IP {
    return net.IPv4(
        byte(ip),
        byte(ip>>8),
        byte(ip>>16),
        byte(ip>>24),
    )
}
