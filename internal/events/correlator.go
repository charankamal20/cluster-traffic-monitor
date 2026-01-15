package events

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// ConnectionKey uniquely identifies a TCP connection using socket pointer
type ConnectionKey struct {
	SockPtr uint64
}

// PendingRequest stores request details waiting for response
type PendingRequest struct {
	ContentLength int64
	RemoteAddr    string
	Host          string
	Timestamp     time.Time
	Method        string
	URL           string
	Headers       map[string]string
	Body          string
	Src           string
	Dst           string // This will be Service IP initially
	IsEncrypted   bool
}

// CorrelatedTrace represents a complete request-response pair
type CorrelatedTrace struct {
	Timestamp       time.Time
	Method          string
	URL             string
	Status          string
	DurationMs      int64
	Src             string
	Dst             string // ⭐ Will be updated to actual backend pod
	RequestHeaders  map[string]string
	RequestBody     string
	ResponseHeaders map[string]string
	ResponseBody    string
	IsEncrypted     bool
}

// Correlator matches HTTP requests with responses
type Correlator struct {
	pending map[ConnectionKey]*PendingRequest
	mu      sync.Mutex
	timeout time.Duration
	ctx     context.Context
	cancel  context.CancelFunc
}

// NewCorrelator creates a new request-response correlator
func NewCorrelator(timeout time.Duration) *Correlator {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Correlator{
		pending: make(map[ConnectionKey]*PendingRequest),
		timeout: timeout,
		ctx:     ctx,
		cancel:  cancel,
	}

	go c.cleanupLoop()
	return c
}

// AddRequest stores a pending request
func (c *Correlator) AddRequest(key ConnectionKey, req *PendingRequest) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pending[key] = req

	slog.Debug("Added pending request",
		"sock_ptr", key.SockPtr,
		"method", req.Method,
		"url", req.URL,
		"dst", req.Dst)
}

// MatchResponse attempts to match a response with a pending request
// ⭐ serverURI: Actual backend pod URI from response source IP
func (c *Correlator) MatchResponse(key ConnectionKey, status string, respHeaders map[string]string, respBody string, timestamp time.Time, serverURI string) *CorrelatedTrace {
	c.mu.Lock()
	defer c.mu.Unlock()

	req, ok := c.pending[key]
	if !ok {
		slog.Warn("No matching request found for response",
			"sock_ptr", key.SockPtr,
			"status", status,
			"pending_count", len(c.pending))
		return nil
	}

	duration := timestamp.Sub(req.Timestamp).Milliseconds()

	trace := &CorrelatedTrace{
		Timestamp:       req.Timestamp,
		Method:          req.Method,
		URL:             req.URL,
		Status:          status,
		DurationMs:      duration,
		Src:             req.Src,
		Dst:             serverURI, // ⭐ USE ACTUAL BACKEND POD FROM RESPONSE
		RequestHeaders:  req.Headers,
		RequestBody:     req.Body,
		ResponseHeaders: respHeaders,
		ResponseBody:    respBody,
		IsEncrypted:     req.IsEncrypted,
	}

	delete(c.pending, key)

	slog.Debug("Matched request-response pair",
		"sock_ptr", key.SockPtr,
		"method", req.Method,
		"status", status,
		"duration_ms", duration,
		"actual_server", serverURI)

	return trace
}

// cleanupLoop periodically removes stale requests
func (c *Correlator) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.cleanup()
		case <-c.ctx.Done():
			return
		}
	}
}

// cleanup removes expired pending requests
func (c *Correlator) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	cleaned := 0
	for key, req := range c.pending {
		if now.Sub(req.Timestamp) > c.timeout {
			delete(c.pending, key)
			cleaned++
		}
	}

	if cleaned > 0 {
		slog.Debug("Cleaned up stale requests", "count", cleaned)
	}
}

// Stop cancels the cleanup goroutine
func (c *Correlator) Stop() {
	c.cancel()
}

// GetPending returns the current pending requests (for debugging)
func (c *Correlator) GetPending() map[ConnectionKey]*PendingRequest {
	c.mu.Lock()
	defer c.mu.Unlock()

	pending := make(map[ConnectionKey]*PendingRequest, len(c.pending))
	for k, v := range c.pending {
		pending[k] = v
	}

	return pending
}
