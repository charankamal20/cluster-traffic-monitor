package filter

import (
	"strings"
)

// Filterer decides which requests should be traced
type Filterer struct {
	ignoredPrefixes   []string
	ignoredExtensions []string
	ignoredUserAgents []string
}

// NewFilterer creates a default filter set
func NewFilterer() *Filterer {
	return &Filterer{
		ignoredPrefixes: []string{
			"/health", "/readyz", "/livez", "/metrics", "/debug",
			"/exa.", // Internal extension server traffic
		},
		ignoredExtensions: []string{
			".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg",
			".css", ".js", ".map", ".woff", ".woff2", ".ttf",
		},
		ignoredUserAgents: []string{
			"kube-probe", "Prometheus", "connect-go",
		},
	}
}

// ShouldTraceConnection checks if a connection (IP flow) should be logged
func (f *Filterer) ShouldTraceConnection(srcIP, dstIP string) bool {
	// Ignore localhost traffic (often internal sidecars or local agents)
	if srcIP == "127.0.0.1" || dstIP == "127.0.0.1" {
		return false
	}
	if srcIP == "::1" || dstIP == "::1" {
		return false
	}
	// Ignore K3s/Flannel Gateway traffic (Noise from probes/infrastructure)
	if srcIP == "10.42.0.1" || dstIP == "10.42.0.1" {
		return false
	}
	return true
}

// ShouldTraceRequest checks if a request should be logged
func (f *Filterer) ShouldTraceRequest(path string, userAgent string) bool {
	// Check Prefixes (Health checks)
	for _, prefix := range f.ignoredPrefixes {
		if strings.HasPrefix(path, prefix) {
			return false
		}
	}

	// Check Extensions (Static assets)
	// Simple check: does it end with extension?
	// Note: Proper URL parsing might be needed for query params,
	// but for this level of efficiency simple suffix check on path is often enough
	// if path is already cleaned of query params.
	for _, ext := range f.ignoredExtensions {
		if strings.HasSuffix(path, ext) {
			return false
		}
	}

	// Check User Agent
	for _, ignoredUA := range f.ignoredUserAgents {
		if strings.Contains(userAgent, ignoredUA) {
			return false
		}
	}

	return true
}
