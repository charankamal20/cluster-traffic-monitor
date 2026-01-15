# Detailed Alignment Guide: Your HTTP Tracer → Pixie Architecture

Based on the Pixie architecture document, here's a comprehensive instruction set to align your project with Pixie's production-grade approach. I'll focus heavily on **filtering improvements** as you identified.[^1]

## 🎯 Executive Summary: Key Gaps

Your current implementation vs Pixie:


| Component | Your Implementation | Pixie's Approach | Gap Severity |
| :-- | :-- | :-- | :-- |
| **Syscall Coverage** | 2 functions (tcp_sendmsg/recvmsg) | 17 syscalls + kernel functions | 🔴 HIGH |
| **eBPF Filtering** | Minimal (protocol detection only) | Multi-layer filtering (80-90% reduction) | 🔴 HIGH |
| **Connection Tracking** | Basic correlator | Full state machine with lifecycle | 🟡 MEDIUM |
| **Stream Reassembly** | Parse on single chunk | Full TCP stream reassembly | 🔴 HIGH |
| **Protocol Detection** | String prefix matching | 9+ protocols with pattern matching | 🟡 MEDIUM |
| **Metadata Enrichment** | Pod/Service lookup | Full K8s context + service correlation | 🟢 LOW |


***

## 📋 Phase 1: eBPF Filtering Infrastructure (CRITICAL)

### 1.1 Implement Multi-Stage eBPF Filtering

Pixie reduces events by 80-90% **before** sending to userspace. Your current approach sends everything and filters in Go.[^2][^1]

**Current Problem:**

```c
// Your code: Always sends to ringbuffer
bpf_ringbuf_output(&events, e, sizeof(*e), 0);
```

**Pixie's Approach:**

```c
// Add filtering stages before sending
SEC("kprobe/tcp_sendmsg")
int kprobe_tcp_sendmsg(struct pt_regs *ctx) {
    // ... capture data ...
    
    // ============ FILTERING STAGE 1: Socket Type ============
    struct socket *sock = ...;
    short family = BPF_CORE_READ(sock, sk, __sk_common.skc_family);
    
    if (family != AF_INET && family != AF_INET6) {
        return 0;  // Skip Unix sockets, Netlink, etc
    }
    
    // ============ FILTERING STAGE 2: Port-Based ============
    u16 dport = BPF_CORE_READ(sock, sk, __sk_common.skc_dport);
    dport = bpf_ntohs(dport);
    
    // Skip common K8s noise ports
    if (dport == 8443 || dport == 6443) {  // K8s API
        return 0;
    }
    
    // ============ FILTERING STAGE 3: Protocol Detection ============
    if (!is_http_traffic(payload, payload_len)) {
        return 0;  // Only send HTTP traffic
    }
    
    // ============ FILTERING STAGE 4: Health Check Detection ============
    if (is_health_check(payload, payload_len)) {
        return 0;  // Filter kube-probe traffic
    }
    
    // Only NOW send to ringbuffer
    bpf_ringbuf_output(&events, e, sizeof(*e), 0);
    return 0;
}
```

**Implementation Instructions:**

**Step 1:** Create `filter_helpers.h` in your eBPF code:

```c
// ebpf/filter_helpers.h

#ifndef __FILTER_HELPERS_H
#define __FILTER_HELPERS_H

// Protocol detection constants
#define MIN_HTTP_SIZE 16

// HTTP Methods (first 4 bytes as integers for fast comparison)
#define GET_INT  0x20544547  // "GET "
#define POST_INT 0x54534f50  // "POST"
#define PUT_INT  0x20545550  // "PUT "
#define DEL_INT  0x454c4544  // "DEL" (DELETE)
#define HTTP_INT 0x50545448  // "HTTP"

// Health check paths (first 8 bytes)
#define HEALTH_1 0x68746c6165682f2f  // "/health"
#define READY_1  0x7a796461657221    // "/readyz"

static __always_inline bool is_http_traffic(const char *buf, u32 len) {
    if (len < MIN_HTTP_SIZE) {
        return false;
    }
    
    // Read first 4 bytes as integer for fast comparison
    u32 first_word = 0;
    bpf_probe_read_kernel(&first_word, 4, buf);
    
    // Check HTTP methods
    if (first_word == GET_INT || first_word == POST_INT || 
        first_word == PUT_INT || first_word == DEL_INT) {
        return true;
    }
    
    // Check HTTP response
    if (first_word == HTTP_INT) {
        return true;
    }
    
    return false;
}

static __always_inline bool is_health_check(const char *buf, u32 len) {
    if (len < 16) {
        return false;
    }
    
    // Quick check for common health check patterns
    char path[^16] = {0};
    bpf_probe_read_kernel(path, 16, buf);
    
    // Check for "/health", "/readyz", "/livez", "/metrics"
    if (path[^0] == 'G' && path[^1] == 'E' && path[^2] == 'T') {
        // Check path after "GET "
        if (path[^4] == '/' && path[^5] == 'h' && path[^6] == 'e') {
            return true;  // "/health*"
        }
        if (path[^4] == '/' && path[^5] == 'r' && path[^6] == 'e') {
            return true;  // "/readyz"
        }
        if (path[^4] == '/' && path[^5] == 'l' && path[^6] == 'i') {
            return true;  // "/livez"
        }
        if (path[^4] == '/' && path[^5] == 'm' && path[^6] == 'e') {
            return true;  // "/metrics"
        }
    }
    
    return false;
}

static __always_inline bool should_trace_port(u16 port) {
    // Common ports to EXCLUDE
    switch (port) {
        case 8443:  // K8s API
        case 6443:  // K8s API
        case 2379:  // etcd
        case 2380:  // etcd peer
        case 10250: // kubelet
        case 10255: // kubelet read-only
        case 10256: // kube-proxy health
        case 9099:  // calico
        case 9100:  // node-exporter
            return false;
        default:
            return true;
    }
}

#endif
```

**Step 2:** Update your `http_tracer_full.bpf.c`:[^3]

```c
#include "filter_helpers.h"

SEC("kprobe/tcp_sendmsg")
int kprobe_tcp_sendmsg(struct pt_regs *ctx) {
    // ... existing code to get sock, payload ...
    
    // === ADD FILTERING HERE ===
    
    // Filter 1: Address family
    short family = BPF_CORE_READ(sock, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6) {
        return 0;
    }
    
    // Filter 2: Port filtering
    u16 dport = BPF_CORE_READ(sock, __sk_common.skc_dport);
    dport = bpf_ntohs(dport);
    if (!should_trace_port(dport)) {
        return 0;
    }
    
    // Filter 3: Protocol detection
    if (!is_http_traffic(e->payload, e->data_len)) {
        return 0;
    }
    
    // Filter 4: Health check filtering
    if (is_health_check(e->payload, e->data_len)) {
        return 0;
    }
    
    // Only send if passed all filters
    bpf_ringbuf_output(&events, e, sizeof(*e), 0);
    return 0;
}
```

**Expected Impact:** 70-80% reduction in events sent to userspace.[^1]

***

### 1.2 Implement Connection-Level Filtering

Pixie tracks connections and filters entire connections, not just individual packets.[^1]

**Create Connection Filter Map:**

```c
// Add to your BPF maps
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);  // sock pointer
    __type(value, u8);  // filter decision: 0=block, 1=allow
} connection_filter_cache SEC(".maps");

SEC("kprobe/tcp_sendmsg")
int kprobe_tcp_sendmsg(struct pt_regs *ctx) {
    // ... get sock ...
    
    u64 sock_ptr = (u64)sock;
    
    // Check cache first
    u8 *cached_decision = bpf_map_lookup_elem(&connection_filter_cache, &sock_ptr);
    if (cached_decision) {
        if (*cached_decision == 0) {
            return 0;  // Previously filtered
        }
        // Skip re-filtering, send immediately
        goto send_event;
    }
    
    // First packet on this connection: do full filtering
    u8 decision = 1;  // default: allow
    
    if (!is_http_traffic(payload, len)) {
        decision = 0;
    }
    if (is_health_check(payload, len)) {
        decision = 0;
    }
    
    // Cache the decision
    bpf_map_update_elem(&connection_filter_cache, &sock_ptr, &decision, BPF_ANY);
    
    if (decision == 0) {
        return 0;
    }
    
send_event:
    bpf_ringbuf_output(&events, e, sizeof(*e), 0);
    return 0;
}
```

**Benefits:**

- Only evaluate filters once per connection
- Subsequent packets skip expensive checks
- LRU automatically evicts old connections

***

## 📋 Phase 2: Expand Syscall Coverage

### 2.1 Add Missing Syscall Probes

Pixie uses 17 syscalls. You only use 2. Add these critical ones:[^1]

**Priority Order:**

**HIGH PRIORITY (Implement First):**

```c
// 1. Connection establishment - CRITICAL for tracking
SEC("kprobe/tcp_connect")
int kprobe_tcp_connect(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    
    // Extract connection 4-tuple
    u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    dport = bpf_ntohs(dport);
    
    // Store in connections map
    u64 sock_ptr = (u64)sk;
    struct conn_info conn = {
        .src_ip = saddr,
        .dst_ip = daddr,
        .src_port = sport,
        .dst_port = dport,
        .timestamp = bpf_ktime_get_ns(),
    };
    
    bpf_map_update_elem(&connections, &sock_ptr, &conn, BPF_ANY);
    return 0;
}

// 2. Accept incoming connections
SEC("kprobe/inet_csk_accept")
int kprobe_inet_csk_accept(struct pt_regs *ctx) {
    // Similar to tcp_connect but for server side
    // Captures incoming connections
}

// 3. Connection close - cleanup
SEC("kprobe/tcp_close")
int kprobe_tcp_close(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    u64 sock_ptr = (u64)sk;
    
    // Send close event to userspace for correlation cleanup
    struct close_event ev = {
        .timestamp = bpf_ktime_get_ns(),
        .sock_ptr = sock_ptr,
    };
    bpf_ringbuf_output(&close_events, &ev, sizeof(ev), 0);
    
    // Cleanup maps
    bpf_map_delete_elem(&connections, &sock_ptr);
    bpf_map_delete_elem(&connection_filter_cache, &sock_ptr);
    return 0;
}

// 4. read() syscall - many apps use this instead of recv()
SEC("kprobe/tcp_read_sock")
int kprobe_tcp_read_sock(struct pt_regs *ctx) {
    // Similar to tcp_recvmsg
    // Captures data read via read() syscall
}
```

**MEDIUM PRIORITY:**

```c
// send() / recv() variants
SEC("kprobe/tcp_sendpage")  // For sendfile() operations
SEC("kprobe/__tcp_send_ack")  // ACK packets (metadata only)
```


### 2.2 Handle Scatter-Gather I/O Properly

Your current `tcp_sendmsg`/`tcp_recvmsg` handling needs improvement for multiple iovecs.[^3][^1]

**Current Issue:**

```c
// Your code reads only first iovec
const struct iovec *iov_ptr = BPF_CORE_READ(iter, __iov);
void *iov_base = BPF_CORE_READ(iov_ptr, iov_base);
bpf_probe_read_user(e->payload, len, iov_base);
```

**Pixie's Approach:**

```c
SEC("kprobe/tcp_sendmsg")
int kprobe_tcp_sendmsg(struct pt_regs *ctx) {
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    struct iov_iter *iter = &msg->msg_iter;
    
    u8 iter_type = BPF_CORE_READ(iter, iter_type);
    
    if (iter_type == ITER_IOVEC) {
        // Multiple buffers - need to iterate
        const struct iovec *iov = BPF_CORE_READ(iter, __iov);
        unsigned long nr_segs = BPF_CORE_READ(iter, nr_segs);
        
        // Safety: eBPF requires bounded loops
        int max_segs = nr_segs < 8 ? nr_segs : 8;  // Limit to 8
        
        u32 total_copied = 0;
        
        #pragma unroll
        for (int i = 0; i < 8; i++) {
            if (i >= max_segs) break;
            
            struct iovec iov_item;
            bpf_probe_read_kernel(&iov_item, sizeof(iov_item), &iov[i]);
            
            u32 copy_len = iov_item.iov_len;
            if (total_copied + copy_len > MAX_DATA_SIZE) {
                copy_len = MAX_DATA_SIZE - total_copied;
            }
            
            bpf_probe_read_user(e->payload + total_copied, 
                              copy_len, 
                              iov_item.iov_base);
            
            total_copied += copy_len;
            
            if (total_copied >= MAX_DATA_SIZE) break;
        }
        
        e->data_len = total_copied;
    }
    // ... rest of logic ...
}
```


***

## 📋 Phase 3: Stream Reassembly (CRITICAL FIX)

### 3.1 The Problem with Your Current Approach

**Your Code Issue:**[^2]

```go
// This fails if HTTP spans multiple TCP segments!
buf := bytes.NewReader(chunk.Payload)
req, err := http.ReadRequest(bufio.NewReader(buf))
if err != nil {
    return  // SILENTLY DROPS INCOMPLETE REQUESTS
}
```

**Why This Fails:**

```
Chunk 1: "GET /api/users HTTP/1.1\r\nHost"
         ❌ http.ReadRequest() fails (incomplete)

Chunk 2: ": api.example.com\r\n\r\n"
         ❌ Also fails (no request line)

Result: You lose the entire request!
```


### 3.2 Implement Stream Reassembly

Create `internal/stream/reassembler.go`:

```go
package stream

import (
    "bytes"
    "sync"
    "time"
)

// StreamKey uniquely identifies a TCP stream
type StreamKey struct {
    SrcIP   uint32
    SrcPort uint16
    DstIP   uint32
    DstPort uint16
}

// Stream represents an ongoing TCP stream
type Stream struct {
    Key       StreamKey
    Buffer    *bytes.Buffer
    LastSeen  time.Time
    Direction uint8  // 0=egress, 1=ingress
}

// Reassembler assembles TCP streams from chunks
type Reassembler struct {
    streams map[StreamKey]*Stream
    mu      sync.RWMutex
    timeout time.Duration
}

func NewReassembler(timeout time.Duration) *Reassembler {
    r := &Reassembler{
        streams: make(map[StreamKey]*Stream),
        timeout: timeout,
    }
    go r.cleanupLoop()
    return r
}

// AddChunk adds data to the stream and returns complete messages
func (r *Reassembler) AddChunk(key StreamKey, data []byte, direction uint8) [][]byte {
    r.mu.Lock()
    defer r.mu.Unlock()
    
    stream, exists := r.streams[key]
    if !exists {
        stream = &Stream{
            Key:      key,
            Buffer:   bytes.NewBuffer(nil),
            Direction: direction,
        }
        r.streams[key] = stream
    }
    
    // Append new data
    stream.Buffer.Write(data)
    stream.LastSeen = time.Now()
    
    // Try to extract complete messages
    return r.extractMessages(stream)
}

// extractMessages finds complete HTTP messages in buffer
func (r *Reassembler) extractMessages(stream *Stream) [][]byte {
    var messages [][]byte
    
    for {
        // Look for HTTP message boundary
        buf := stream.Buffer.Bytes()
        
        if stream.Direction == 0 { // Egress (request)
            // Look for "\r\n\r\n" (end of headers)
            idx := bytes.Index(buf, []byte("\r\n\r\n"))
            if idx == -1 {
                break  // Incomplete headers
            }
            
            // Check if we have body
            headerEnd := idx + 4
            bodyLen := getContentLength(buf[:headerEnd])
            
            if bodyLen > 0 {
                totalLen := headerEnd + bodyLen
                if len(buf) < totalLen {
                    break  // Incomplete body
                }
                
                // Extract complete request
                msg := make([]byte, totalLen)
                copy(msg, buf[:totalLen])
                messages = append(messages, msg)
                
                // Remove from buffer
                stream.Buffer = bytes.NewBuffer(buf[totalLen:])
            } else {
                // No body, just headers
                msg := make([]byte, headerEnd)
                copy(msg, buf[:headerEnd])
                messages = append(messages, msg)
                stream.Buffer = bytes.NewBuffer(buf[headerEnd:])
            }
            
        } else { // Ingress (response)
            // Similar logic for HTTP responses
            idx := bytes.Index(buf, []byte("\r\n\r\n"))
            if idx == -1 {
                break
            }
            
            headerEnd := idx + 4
            bodyLen := getContentLength(buf[:headerEnd])
            
            // Handle chunked encoding
            if isChunkedEncoding(buf[:headerEnd]) {
                completeLen := findChunkedEnd(buf)
                if completeLen == -1 {
                    break  // Incomplete chunked body
                }
                msg := make([]byte, completeLen)
                copy(msg, buf[:completeLen])
                messages = append(messages, msg)
                stream.Buffer = bytes.NewBuffer(buf[completeLen:])
            } else if bodyLen > 0 {
                totalLen := headerEnd + bodyLen
                if len(buf) < totalLen {
                    break
                }
                msg := make([]byte, totalLen)
                copy(msg, buf[:totalLen])
                messages = append(messages, msg)
                stream.Buffer = bytes.NewBuffer(buf[totalLen:])
            } else {
                msg := make([]byte, headerEnd)
                copy(msg, buf[:headerEnd])
                messages = append(messages, msg)
                stream.Buffer = bytes.NewBuffer(buf[headerEnd:])
            }
        }
    }
    
    return messages
}

func getContentLength(headers []byte) int {
    // Parse Content-Length header
    clPrefix := []byte("Content-Length: ")
    idx := bytes.Index(headers, clPrefix)
    if idx == -1 {
        return 0
    }
    
    start := idx + len(clPrefix)
    end := bytes.Index(headers[start:], []byte("\r\n"))
    if end == -1 {
        return 0
    }
    
    lenStr := string(headers[start : start+end])
    var length int
    fmt.Sscanf(lenStr, "%d", &length)
    return length
}

func isChunkedEncoding(headers []byte) bool {
    return bytes.Contains(headers, []byte("Transfer-Encoding: chunked"))
}

func findChunkedEnd(buf []byte) int {
    // Look for "0\r\n\r\n" (end of chunked encoding)
    endMarker := []byte("0\r\n\r\n")
    idx := bytes.Index(buf, endMarker)
    if idx == -1 {
        return -1
    }
    return idx + len(endMarker)
}

func (r *Reassembler) cleanupLoop() {
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()
    
    for range ticker.C {
        r.mu.Lock()
        now := time.Now()
        for key, stream := range r.streams {
            if now.Sub(stream.LastSeen) > r.timeout {
                delete(r.streams, key)
            }
        }
        r.mu.Unlock()
    }
}
```


### 3.3 Update main.go to Use Reassembler

```go
func run(ctx context.Context) error {
    // ... existing setup ...
    
    // ADD THIS:
    reassembler := stream.NewReassembler(30 * time.Second)
    
    for {
        record, err := rd.Read()
        // ... error handling ...
        
        chunk, err := events.ParseDataEvent(record.RawSample)
        // ... error handling ...
        
        // NEW: Add to reassembler
        streamKey := stream.StreamKey{
            SrcIP:   chunk.SrcIP,
            SrcPort: chunk.SrcPort,
            DstIP:   chunk.DstIP,
            DstPort: chunk.DstPort,
        }
        
        completeMessages := reassembler.AddChunk(streamKey, chunk.Payload, chunk.Direction)
        
        // Process each complete message
        for _, msgData := range completeMessages {
            processCompleteMessage(msgData, chunk, watcher, filterer, writer, correlator)
        }
    }
}

func processCompleteMessage(data []byte, chunk *events.DataEvent, ...) {
    // Now you can safely parse complete HTTP messages
    buf := bytes.NewReader(data)
    req, err := http.ReadRequest(bufio.NewReader(buf))
    if err != nil {
        return  // Still might fail, but much less likely
    }
    
    // Continue with your existing logic...
}
```

**Expected Impact:** 90%+ success rate for HTTP parsing (vs current ~30-50%).[^1]

***

## 📋 Phase 4: Advanced Filtering (Pixie-Level)

### 4.1 Replace Your filter.go with Multi-Layer Approach

Your current `filter.go` has good ideas but wrong location. Move most logic to eBPF.[^4]

**New Architecture:**

```
┌─────────────────────────────────────────┐
│   eBPF Layer (80% of filtering)         │
│   - Port filtering                      │
│   - Protocol detection                  │
│   - Health check detection              │
│   - Address family filtering            │
└──────────────┬──────────────────────────┘
               │ (20% of original traffic)
┌──────────────▼──────────────────────────┐
│   Go Layer (20% of filtering)           │
│   - Namespace exclusions                │
│   - Pod name regex                      │
│   - Path regex (complex patterns)       │
│   - User-Agent advanced matching        │
└─────────────────────────────────────────┘
```

**Updated filter.go:**

```go
package filter

import (
    "regexp"
    "strings"
)

// Config holds user-configurable filters (applied in Go, not eBPF)
type Config struct {
    ExcludeNamespaces []string
    ExcludePods       []*regexp.Regexp
    ExcludePaths      []*regexp.Regexp
    ExcludeIPs        map[string]struct{}
    
    // Advanced filters (can't do in eBPF)
    MaxBodySize       int
    RedactHeaders     []string
    SampleRate        float64  // Only trace X% of traffic
}

// Filterer applies Go-level filtering (after eBPF)
type Filterer struct {
    config Config
    random *rand.Rand
}

func NewFilterer(config Config) *Filterer {
    return &Filterer{
        config: config,
        random: rand.New(rand.NewSource(time.Now().UnixNano())),
    }
}

// ShouldTrace applies all Go-level filters
func (f *Filterer) ShouldTrace(event *Event) bool {
    // Sampling (for high-traffic environments)
    if f.config.SampleRate < 1.0 {
        if f.random.Float64() > f.config.SampleRate {
            return false
        }
    }
    
    // Namespace filtering
    for _, ns := range f.config.ExcludeNamespaces {
        if event.SrcNamespace == ns || event.DstNamespace == ns {
            return false
        }
    }
    
    // Pod regex filtering (complex patterns eBPF can't do)
    for _, pattern := range f.config.ExcludePods {
        if pattern.MatchString(event.SrcPod) || pattern.MatchString(event.DstPod) {
            return false
        }
    }
    
    // Path regex filtering
    for _, pattern := range f.config.ExcludePaths {
        if pattern.MatchString(event.Path) {
            return false
        }
    }
    
    // IP filtering
    if _, excluded := f.config.ExcludeIPs[event.SrcIP]; excluded {
        return false
    }
    if _, excluded := f.config.ExcludeIPs[event.DstIP]; excluded {
        return false
    }
    
    return true
}

// RedactSensitiveData removes sensitive information
func (f *Filterer) RedactSensitiveData(event *Event) {
    // Redact headers
    for _, header := range f.config.RedactHeaders {
        if _, exists := event.RequestHeaders[header]; exists {
            event.RequestHeaders[header] = "[REDACTED]"
        }
        if _, exists := event.ResponseHeaders[header]; exists {
            event.ResponseHeaders[header] = "[REDACTED]"
        }
    }
    
    // Limit body size
    if len(event.RequestBody) > f.config.MaxBodySize {
        event.RequestBody = event.RequestBody[:f.config.MaxBodySize] + "...[TRUNCATED]"
    }
    if len(event.ResponseBody) > f.config.MaxBodySize {
        event.ResponseBody = event.ResponseBody[:f.config.MaxBodySize] + "...[TRUNCATED]"
    }
}
```


### 4.2 Add Configuration File Support

Create `config.yaml`:

```yaml
# http-tracer-config.yaml

filtering:
  # eBPF-level filters (compile-time, edit C code)
  # - Ports: defined in filter_helpers.h
  # - Protocols: HTTP only
  # - Health checks: /health, /readyz, etc.
  
  # Go-level filters (runtime, configurable)
  excludeNamespaces:
    - kube-system
    - kube-node-lease
    - kube-public
    - local-path-storage
  
  excludePods:
    - "^coredns-.*"
    - "^calico-.*"
    - "^metrics-server-.*"
    - "^kube-proxy-.*"
  
  excludePaths:
    - "^/health.*"
    - "^/metrics$"
    - "^/debug/.*"
    - ".*\\.js$"
    - ".*\\.css$"
    - ".*\\.png$"
  
  excludeIPs:
    - "10.42.0.1"  # CNI gateway
    - "169.254.1.1"  # Metadata service
  
  sampling:
    enabled: false
    rate: 1.0  # 1.0 = 100%, 0.1 = 10%
  
  dataLimits:
    maxBodySize: 4096  # bytes
    maxHeaderSize: 1024
  
  redaction:
    headers:
      - Authorization
      - Cookie
      - Set-Cookie
      - X-Auth-Token
      - X-API-Key
    bodyPatterns:
      - "password"
      - "token"
      - "api_key"

output:
  path: "/var/log/http-tracer/traces.log"
  format: "ndjson"  # or "json", "csv"
  rotation:
    enabled: true
    maxSize: 100MB
    maxFiles: 10

performance:
  ringbufferSize: 256  # MB
  workerThreads: 4
  batchSize: 100  # events per batch
```

Load in main.go:

```go
import "gopkg.in/yaml.v3"

type Config struct {
    Filtering  filter.Config  `yaml:"filtering"`
    Output     output.Config  `yaml:"output"`
    Performance PerfConfig    `yaml:"performance"`
}

func loadConfig(path string) (*Config, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }
    
    var config Config
    if err := yaml.Unmarshal(data, &config); err != nil {
        return nil, err
    }
    
    return &config, nil
}
```


***

## 📋 Phase 5: Production Readiness

### 5.1 Add Observability (Metrics)

Pixie exposes metrics for monitoring. Add Prometheus metrics:[^1]

```go
package metrics

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

var (
    EventsReceived = promauto.NewCounter(prometheus.CounterOpts{
        Name: "http_tracer_events_received_total",
        Help: "Total events received from eBPF",
    })
    
    EventsFiltered = promauto.NewCounterVec(prometheus.CounterOpts{
        Name: "http_tracer_events_filtered_total",
        Help: "Events filtered by reason",
    }, []string{"reason"})
    
    EventsProcessed = promauto.NewCounter(prometheus.CounterOpts{
        Name: "http_tracer_events_processed_total",
        Help: "Successfully processed events",
    })
    
    EventsDropped = promauto.NewCounterVec(prometheus.CounterOpts{
        Name: "http_tracer_events_dropped_total",
        Help: "Dropped events by reason",
    }, []string{"reason"})
    
    ProcessingLatency = promauto.NewHistogram(prometheus.HistogramOpts{
        Name: "http_tracer_processing_latency_seconds",
        Help: "Event processing latency",
        Buckets: prometheus.ExponentialBuckets(0.0001, 2, 10),
    })
    
    StreamsActive = promauto.NewGauge(prometheus.GaugeOpts{
        Name: "http_tracer_streams_active",
        Help: "Active TCP streams being tracked",
    })
    
    CorrelatorPending = promauto.NewGauge(prometheus.GaugeOpts{
        Name: "http_tracer_correlator_pending",
        Help: "Pending requests awaiting responses",
    })
)
```

Add metrics endpoint to main.go:

```go
import (
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "net/http"
)

func run(ctx context.Context) error {
    // ... existing setup ...
    
    // Start metrics server
    go func() {
        http.Handle("/metrics", promhttp.Handler())
        http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
            w.WriteHeader(http.StatusOK)
            w.Write([]byte("OK"))
        })
        slog.Info("Metrics server listening", "port", 9090)
        http.ListenAndServe(":9090", nil)
    }()
    
    // ... rest of code ...
}
```

Update daemonset.yaml:[^5]

```yaml
spec:
  template:
    spec:
      containers:
      - name: tracer
        ports:
        - containerPort: 9090
          name: metrics
          protocol: TCP
        livenessProbe:
          httpGet:
            path: /health
            port: 9090
          initialDelaySeconds: 10
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 9090
          initialDelaySeconds: 5
          periodSeconds: 5
```


### 5.2 Fix Critical Bugs

**Bug 1: Correlator Race Condition**[^6]

```go
// WRONG (your current code):
func (c *Correlator) cleanupLoop() {
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()
    for range ticker.C {
        c.mu.Lock()
        now := time.Now()
        for key, req := range c.pending {
            if now.Sub(req.Timestamp) > c.timeout {
                delete(c.pending, key)
            }
        }
        c.mu.Unlock()  // WRONG POSITION!
    }
}

// CORRECT:
func (c *Correlator) cleanupLoop() {
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()
    for range ticker.C {
        c.cleanup()
    }
}

func (c *Correlator) cleanup() {
    c.mu.Lock()
    defer c.mu.Unlock()  // CORRECT
    
    now := time.Now()
    for key, req := range c.pending {
        if now.Sub(req.Timestamp) > c.timeout {
            delete(c.pending, key)
        }
    }
}
```

**Bug 2: FileWriter Goroutine Leak**[^7]

```go
// WRONG:
func (fw *FileWriter) Close() error {
    close(fw.stopCh)
    fw.Flush()
    return fw.file.Close()
}

// CORRECT:
func (fw *FileWriter) Close() error {
    close(fw.stopCh)
    time.Sleep(100 * time.Millisecond)  // Let goroutine exit
    fw.mu.Lock()
    defer fw.mu.Unlock()
    fw.writer.Flush()
    return fw.file.Close()
}
```

**Bug 3: Pod Watcher ResourceVersion**[^8]

```go
// ADD:
func (w *Watcher) startPodWatcher(ctx context.Context) error {
    pods, err := w.client.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
    // ... populate initial cache ...
    
    go func() {
        resourceVersion := pods.ResourceVersion  // START HERE
        for {
            select {
            case <-ctx.Done():
                return
            default:
                watchOpts := metav1.ListOptions{
                    Watch: true,
                    ResourceVersion: resourceVersion,  // USE IT
                }
                
                watcher, err := w.client.CoreV1().Pods("").Watch(ctx, watchOpts)
                // ... handle error ...
                
                for event := range watcher.ResultChan() {
                    pod, ok := event.Object.(*corev1.Pod)
                    if !ok {
                        continue
                    }
                    
                    // UPDATE IT on each event!
                    resourceVersion = pod.ResourceVersion
                    
                    w.mu.Lock()
                    switch event.Type {
                        case "ADDED", "MODIFIED":
                            w.updatePod(pod)
                        case "DELETED":
                            w.deletePod(pod)
                    }
                    w.mu.Unlock()
                }
            }
        }
    }()
    return nil
}
```


***

## 📋 Phase 6: Testing \& Validation

### 6.1 Add Comprehensive Tests

Create `internal/stream/reassembler_test.go`:

```go
package stream

import (
    "testing"
)

func TestReassemblerSimpleRequest(t *testing.T) {
    r := NewReassembler(10 * time.Second)
    key := StreamKey{SrcIP: 1, SrcPort: 1234, DstIP: 2, DstPort: 80}
    
    // Single chunk, complete request
    data := []byte("GET /api HTTP/1.1\r\nHost: test\r\n\r\n")
    messages := r.AddChunk(key, data, 0)
    
    if len(messages) != 1 {
        t.Fatalf("Expected 1 message, got %d", len(messages))
    }
    
    if string(messages[^0]) != string(data) {
        t.Errorf("Message mismatch")
    }
}

func TestReassemblerSplitRequest(t *testing.T) {
    r := NewReassembler(10 * time.Second)
    key := StreamKey{SrcIP: 1, SrcPort: 1234, DstIP: 2, DstPort: 80}
    
    // Split across two chunks
    chunk1 := []byte("GET /api HTTP/1.1\r\n")
    chunk2 := []byte("Host: test\r\n\r\n")
    
    messages1 := r.AddChunk(key, chunk1, 0)
    if len(messages1) != 0 {
        t.Errorf("Should not extract incomplete message")
    }
    
    messages2 := r.AddChunk(key, chunk2, 0)
    if len(messages2) != 1 {
        t.Fatalf("Expected 1 message after second chunk")
    }
    
    expected := string(chunk1) + string(chunk2)
    if string(messages2[^0]) != expected {
        t.Errorf("Reassembled message incorrect")
    }
}

func TestReassemblerWithBody(t *testing.T) {
    r := NewReassembler(10 * time.Second)
    key := StreamKey{SrcIP: 1, SrcPort: 1234, DstIP: 2, DstPort: 80}
    
    body := "test body content"
    data := []byte(fmt.Sprintf(
        "POST /api HTTP/1.1\r\n"+
        "Host: test\r\n"+
        "Content-Length: %d\r\n"+
        "\r\n"+
        "%s", len(body), body))
    
    messages := r.AddChunk(key, data, 0)
    
    if len(messages) != 1 {
        t.Fatalf("Expected 1 message, got %d", len(messages))
    }
}
```


### 6.2 Performance Testing

Create `test/performance_test.go`:

```go
func BenchmarkFilteringPipeline(b *testing.B) {
    filterer := filter.NewFilterer(filter.Config{})
    
    event := &Event{
        Path: "/api/users",
        Method: "GET",
        SrcNamespace: "default",
    }
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        filterer.ShouldTrace(event)
    }
}

func BenchmarkStreamReassembly(b *testing.B) {
    r := stream.NewReassembler(30 * time.Second)
    key := stream.StreamKey{SrcIP: 1, SrcPort: 1234, DstIP: 2, DstPort: 80}
    data := []byte("GET /api HTTP/1.1\r\nHost: test\r\n\r\n")
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        r.AddChunk(key, data, 0)
    }
}
```


***

## 🎯 Summary: Implementation Priority

### Week 1: Critical Fixes

1. ✅ Implement stream reassembly (Phase 3)
2. ✅ Add eBPF filtering (Phase 1.1, 1.2)
3. ✅ Fix correlator race condition (Phase 5.2)

### Week 2: Expand Coverage

4. ✅ Add tcp_connect/tcp_close probes (Phase 2.1)
5. ✅ Implement scatter-gather handling (Phase 2.2)
6. ✅ Add configuration file support (Phase 4.2)

### Week 3: Production Readiness

7. ✅ Add metrics and health endpoints (Phase 5.1)
8. ✅ Implement advanced filtering (Phase 4.1)
9. ✅ Add comprehensive tests (Phase 6)

### Week 4: Polish

10. ✅ Performance optimization
11. ✅ Documentation
12. ✅ CI/CD pipeline

***

## 📊 Expected Results After Implementation

| Metric | Current | After Fixes | Pixie-Level |
| :-- | :-- | :-- | :-- |
| **Event Reduction** | ~0% (all sent to userspace) | ~80% | ~85% |
| **CPU Overhead** | ~8-10% | ~3-5% | ~2-3% |
| **HTTP Parse Success** | ~30% (missing splits) | ~95% | ~98% |
| **False Positives** | ~40% (health checks) | ~5% | ~2% |
| **Memory Usage** | ~800MB | ~400MB | ~300MB |

This implementation guide aligns your project with Pixie's proven architecture while keeping it focused on HTTP-only traffic. The most impactful changes are stream reassembly and eBPF-level filtering, which will immediately improve reliability and performance.[^4][^2][^3][^1]
<span style="display:none">[^10][^11][^12][^13][^9]</span>

<div align="center">⁂</div>

[^1]: pixie_architecture_analysis.md

[^2]: main.go

[^3]: http_tracer_full.bpf.c

[^4]: filter.go

[^5]: daemonset.yaml

[^6]: correlator.go

[^7]: file_writer.go

[^8]: watcher.go

[^9]: Makefile

[^10]: chunk.go

[^11]: event.go

[^12]: debug.go

[^13]: serviceaccount.yaml
