package filter

import (
	"strings"
)

// Filterer decides which requests should be traced
type Filterer struct {
	// User control - explicit EXCLUDES (Blacklist)
	excludeNamespaces []string
	excludePods       []string // Regex
	excludePaths      []string // Regex (replaces ignoredPrefixes for more power, but we keep prefixes for simple speed if needed)
	excludeIPs        map[string]struct{}

	// Defaults / Built-ins (from Pixie recommendations)
	ignoredPrefixes   []string
	ignoredExtensions []string
	ignoredUserAgents []string
}

// NewFilterer creates a default filter set
func NewFilterer() *Filterer {
	return &Filterer{
		// Recommended defaults (noise reduction)
		excludeNamespaces: []string{
			"kube-system",
			"kube-node-lease",
			"local-path-storage",
		},
		excludePods: []string{
			"coredns-.*",
			"calico-.*",
			"csi-.*",
		},
		excludePaths: []string{
			"/health.*",
			"/metrics",
			"/readyz",
			"/livez",
		},
		excludeIPs: map[string]struct{}{
			// "10.42.0.1": {}, // CNI Gateway / Node Probes only
		},
		// Keep existing simple checks
		ignoredPrefixes: []string{
			"/health", "/readyz", "/livez", "/metrics", "/debug",
			"/exa.",
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

// ShouldTraceConnection checks if a connection should be logged based on IP and Metadata
func (f *Filterer) ShouldTraceConnection(srcPod, dstPod, srcNs, dstNs string) bool {
	// 1. Namespace Filtering
	for _, ns := range f.excludeNamespaces {
		if srcNs == ns || dstNs == ns {
			return false
		}
	}

	// 2. Pod Name Filtering
	// NOTE: using Contains for simplicity, could use regexp.MatchString for full power
	for _, pattern := range f.excludePods {
		// Simple wildcard support: if ends in -.*, check prefix
		if strings.HasSuffix(pattern, "-.*") {
			prefix := strings.TrimSuffix(pattern, "-.*")
			if strings.HasPrefix(srcPod, prefix) || strings.HasPrefix(dstPod, prefix) {
				return false
			}
		} else {
			if strings.Contains(srcPod, pattern) || strings.Contains(dstPod, pattern) {
				return false
			}
		}
	}

	return true
}

// ShouldTraceIP checks if an IP should be logged
func (f *Filterer) ShouldTraceIP(ip string) bool {
	if _, ok := f.excludeIPs[ip]; ok {
		return false
	}
	return true
}

// IsHealthProbe detects if a request/response is a health probe
// These should be filtered even on localhost
func (f *Filterer) IsHealthProbe(path, userAgent, responseBody string) bool {
	// Check User-Agent
	for _, ua := range f.ignoredUserAgents {
		if strings.Contains(userAgent, ua) {
			return true
		}
	}

	// Check Path
	for _, prefix := range f.ignoredPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}

	// Check Response Body (common health check responses)
	if responseBody == "ok" || responseBody == "OK" {
		return true
	}

	return false
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

	// Check Exclude Paths (Regex-like)
	for _, pattern := range f.excludePaths {
		// Handle simple * wildcard
		if strings.HasSuffix(pattern, ".*") {
			prefix := strings.TrimSuffix(pattern, ".*")
			if strings.HasPrefix(path, prefix) {
				return false
			}
		} else {
			if path == pattern {
				return false
			}
		}
	}

	return true
}

func (f *Filterer) IsLoopbackTraffic(srcIP, dstIP string) bool {
    isLoopback := func(ip string) bool {
        return ip == "127.0.0.1" || ip == "::1" || strings.HasPrefix(ip, "127.")
    }
    
    // Only filter if BOTH src and dst are localhost
    return isLoopback(srcIP) && isLoopback(dstIP)
}
