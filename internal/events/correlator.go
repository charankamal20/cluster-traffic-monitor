package events

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// ConnectionKey uniquely identifies a TCP connection
type ConnectionKey struct {
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
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
	Dst           string
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
	Dst             string
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

	// Start cleanup goroutine
	go c.cleanupLoop()

	return c
}

// AddRequest stores a pending request
func (c *Correlator) AddRequest(key ConnectionKey, req *PendingRequest) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pending[key] = req
}

// MatchResponse attempts to match a response with a pending request
// Returns the correlated trace if found, nil otherwise
func (c *Correlator) MatchResponse(key ConnectionKey, status string, respHeaders map[string]string, respBody string, timestamp time.Time) *CorrelatedTrace {
	c.mu.Lock()
	defer c.mu.Unlock()

	req, ok := c.pending[key]
	if !ok {
		// ⭐ Add debug logging
		slog.Warn("No matching request found for response",
			"key", fmt.Sprintf("%s:%d->%s:%d", key.SrcIP, key.SrcPort, key.DstIP, key.DstPort),
			"status", status,
			"pending_count", len(c.pending))

		// Show what keys we DO have
		if len(c.pending) > 0 {
			slog.Info("Currently pending requests:")
			for k := range c.pending {
				slog.Info("  Pending:", "key", fmt.Sprintf("%s:%d->%s:%d", k.SrcIP, k.SrcPort, k.DstIP, k.DstPort))
			}
		}
		return nil
	}

	// Calculate duration
	duration := timestamp.Sub(req.Timestamp).Milliseconds()

	// Create correlated trace
	trace := &CorrelatedTrace{
		Timestamp:       req.Timestamp,
		Method:          req.Method,
		URL:             req.URL,
		Status:          status,
		DurationMs:      duration,
		Src:             req.Src,
		Dst:             req.Dst,
		RequestHeaders:  req.Headers,
		RequestBody:     req.Body,
		ResponseHeaders: respHeaders,
		ResponseBody:    respBody,
		IsEncrypted:     req.IsEncrypted,
	}

	// Remove from pending
	delete(c.pending, key)

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
	for key, req := range c.pending {
		if now.Sub(req.Timestamp) > c.timeout {
			delete(c.pending, key)
		}
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

	// Return a copy to avoid race conditions
	pending := make(map[ConnectionKey]*PendingRequest, len(c.pending))
	for k, v := range c.pending {
		pending[k] = v
	}
	return pending
}
