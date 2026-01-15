package output

import (
	"strings"
)

// sensitiveHeaders are HTTP headers that should be redacted
var sensitiveHeaders = map[string]bool{
	"authorization":       true,
	"cookie":              true,
	"set-cookie":          true,
	"x-api-key":           true,
	"api-key":             true,
	"x-auth-token":        true,
	"proxy-authorization": true,
}

// RedactHeaders redacts sensitive header values
func RedactHeaders(headers map[string]string) map[string]string {
	redacted := make(map[string]string, len(headers))
	for k, v := range headers {
		headerLower := strings.ToLower(k)
		if sensitiveHeaders[headerLower] {
			redacted[k] = "[REDACTED]"
		} else {
			redacted[k] = v
		}
	}
	return redacted
}

// TruncateBody limits body size to prevent excessive data capture
func TruncateBody(body string, maxSize int) string {
	if maxSize <= 0 {
		maxSize = 8192 // Default 8KB
	}
	if len(body) > maxSize {
		return body[:maxSize] + "... [TRUNCATED]"
	}
	return body
}
