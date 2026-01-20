package http2

import (
	"bytes"
	"fmt"

	"golang.org/x/net/http2/hpack"
)

// HPACKDecoder wraps the standard HPACK decoder with additional functionality
type HPACKDecoder struct {
	decoder *hpack.Decoder
	maxSize uint32
}

// NewHPACKDecoder creates a new HPACK decoder with proper initialization
func NewHPACKDecoder(maxDynamicTableSize uint32) *HPACKDecoder {
	if maxDynamicTableSize == 0 {
		maxDynamicTableSize = 4096 // Default per HTTP/2 spec
	}

	return &HPACKDecoder{
		decoder: hpack.NewDecoder(maxDynamicTableSize, nil),
		maxSize: maxDynamicTableSize,
	}
}

// DecodeHeaders decodes HPACK-encoded header block
func (d *HPACKDecoder) DecodeHeaders(data []byte) ([]hpack.HeaderField, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var headers []hpack.HeaderField
	d.decoder.SetEmitFunc(func(hf hpack.HeaderField) {
		headers = append(headers, hf)
	})

	reader := bytes.NewReader(data)
	if _, err := d.decoder.Write(data); err != nil {
		return nil, fmt.Errorf("HPACK decode error: %w", err)
	}

	// Check for incomplete decode
	if reader.Len() > 0 {
		return headers, fmt.Errorf("incomplete HPACK decode, %d bytes remaining", reader.Len())
	}

	return headers, nil
}

// Reset resets the decoder state
func (d *HPACKDecoder) Reset() {
	d.decoder = hpack.NewDecoder(d.maxSize, nil)
}

// SetMaxDynamicTableSize updates the dynamic table size
func (d *HPACKDecoder) SetMaxDynamicTableSize(size uint32) {
	d.maxSize = size
	d.decoder.SetMaxDynamicTableSize(size)
}

// HeadersToMap converts HeaderField slice to map for easier access
func HeadersToMap(headers []hpack.HeaderField) map[string]string {
	m := make(map[string]string, len(headers))
	for _, hf := range headers {
		// For duplicate headers, concatenate with comma (per HTTP spec)
		if existing, ok := m[hf.Name]; ok {
			m[hf.Name] = existing + ", " + hf.Value
		} else {
			m[hf.Name] = hf.Value
		}
	}
	return m
}

// ExtractPseudoHeaders extracts HTTP/2 pseudo-headers
func ExtractPseudoHeaders(headers []hpack.HeaderField) (method, path, scheme, authority, status string) {
	for _, hf := range headers {
		switch hf.Name {
		case ":method":
			method = hf.Value
		case ":path":
			path = hf.Value
		case ":scheme":
			scheme = hf.Value
		case ":authority":
			authority = hf.Value
		case ":status":
			status = hf.Value
		}
	}
	return
}
