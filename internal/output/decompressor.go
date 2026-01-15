package output

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
)

// DecompressBody attempts to decompress HTTP body based on Content-Encoding header
func DecompressBody(body []byte, contentEncoding string) ([]byte, error) {
	encoding := strings.ToLower(strings.TrimSpace(contentEncoding))

	switch encoding {
	case "gzip":
		return decompressGzip(body)
	case "deflate":
		return decompressDeflate(body)
	case "br", "brotli":
		return decompressBrotli(body)
	case "", "identity":
		// No compression
		return body, nil
	default:
		// Unknown encoding, return as-is
		return body, nil
	}
}

func decompressGzip(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return data, err // Return original on error
	}
	defer reader.Close()

	decompressed, err := io.ReadAll(reader)
	if err != nil {
		return data, err
	}

	return decompressed, nil
}

func decompressDeflate(data []byte) ([]byte, error) {
	reader, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return data, err
	}
	defer reader.Close()

	decompressed, err := io.ReadAll(reader)
	if err != nil {
		return data, err
	}

	return decompressed, nil
}

func decompressBrotli(data []byte) ([]byte, error) {
	reader := brotli.NewReader(bytes.NewReader(data))
	decompressed, err := io.ReadAll(reader)
	if err != nil {
		return data, err
	}

	return decompressed, nil
}

// GetContentEncoding extracts Content-Encoding header value
func GetContentEncoding(headers map[string]string) string {
	// Check both capitalization variants
	if enc, ok := headers["Content-Encoding"]; ok {
		return enc
	}
	if enc, ok := headers["content-encoding"]; ok {
		return enc
	}
	return ""
}
