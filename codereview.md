<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" style="height:64px;margin-right:32px"/>

# I am asking you to do a code review. I am providing you with my code files.

It is code to leverage ebpf to catch all http traffic inside a kubernetes cluster.

I'll provide a comprehensive code review of your eBPF-based HTTP traffic monitoring tool for Kubernetes. This is an impressive project combining kernel-level tracing with Kubernetes metadata enrichment.[^1][^2][^3]

## Architecture \& Design

Your tool uses eBPF kprobes to capture TCP traffic at kernel level, parses HTTP from raw payloads, and enriches data with Kubernetes pod/service information. The overall architecture is solid with good separation of concerns.[^2][^3]

## Critical Issues

### eBPF Code (`http_tracer_full.bpf.c`)

**Memory Safety \& Buffer Handling**

- The `MAX_DATA_SIZE` is set to 30720 bytes, which may exceed eBPF stack/map limits. The verifier typically allows much smaller buffers. Consider reducing to 4096 or using chunking.[^3]
- The `bpf_ringbuf_output` sends the entire `struct data_event` including unused payload space, wasting bandwidth. Use dynamic sizing: `bpf_ringbuf_output(&events, e, sizeof(*e) - MAX_DATA_SIZE + e->data_len, 0);`[^3]

**Incomplete Ingress Capture**

- Your `kprobe/tcp_cleanup_rbuf` returns 0 without capturing data. The ingress path relies on `kretprobe/tcp_recvmsg`, but the payload reading logic has issues:[^3]
    - The iter pointer calculation `(struct iov_iter *)(args->msg + offsetof(struct msghdr, msg_iter))` is unsafe. You should use `BPF_CORE_READ` to properly access the field.
    - In kretprobe, the `iov_iter` may already be consumed/advanced by the kernel, making reads unreliable.

**Missing Error Handling**

- No validation that connections are IPv4 before accessing IPv4 fields[^3]
- Missing bounds checking on `iov_base` pointer validity before `bpf_probe_read_user`


### Go Code Issues

**Correlator Race Condition** (`correlator.go`)

- The `cleanupLoop` has a critical bug: you unlock `c.mu` inside the range loop, but then try to use it again in the next iteration:[^4]

```go
for range ticker.C {
    c.mu.Lock()
    for key, req := range c.pending {
        if now.Sub(req.Timestamp) > c.timeout {
            delete(c.pending, key)
        }
    }
    c.mu.Unlock() // This should be AFTER the loop
}
```

This creates a race where the map is accessed without lock protection.

**Memory Leaks**

- The `active_recv` map in eBPF is only cleaned on successful reads, but never on errors/timeouts. Consider adding periodic cleanup.[^3]
- `watcher.go` doesn't properly handle service deletion - the comment acknowledges this. The current implementation iterates the entire map on each endpoint delete, which is O(n).[^5]

**HTTP Parsing Issues** (`main.go`)

- Using `http.ReadRequest` and `http.ReadResponse` on potentially incomplete buffers will fail frequently. HTTP messages may span multiple TCP segments. You need:[^2]
    - Stream reassembly per connection
    - Buffering until complete HTTP message
    - Timeout/cleanup for incomplete messages

**Goroutine Leak** (`file_writer.go`)

- The `flushLoop` goroutine never exits when Close() is called because closing `stopCh` happens after `Flush()`:[^6]

```go
func (fw *FileWriter) Close() error {
    close(fw.stopCh)  // May not be received immediately
    fw.Flush()        // This could deadlock if flushLoop holds lock
    return fw.file.Close()
}
```

**Pod Watcher ResourceVersion Bug** (`watcher.go`)

- The `startPodWatcher` goroutine closes over `pods.ResourceVersion`, but this variable is from the initial list and never updated in the watch loop. When the watch reconnects, it reuses a stale ResourceVersion. You need to update it from watch events.[^5]


## Security Concerns

**Privileged Container**

- The DaemonSet runs with `privileged: true` and `hostNetwork: true`. While necessary for eBPF, consider:[^7]
    - Using AppArmor/SELinux profiles
    - Dropping unnecessary capabilities after initialization
    - Running as non-root user ID where possible

**Sensitive Data Exposure**

- You're capturing full HTTP request/response bodies including potentially sensitive data (auth tokens, passwords, PII). Add:[^6]
    - Redaction for known sensitive headers (Authorization, Cookie, etc.)
    - Body size limits
    - Option to disable body capture
    - Encryption at rest for trace logs

**RBAC Overpermission**

- The ClusterRole grants `watch` on all pods/nodes/endpoints cluster-wide. Consider using namespace-scoped Roles where possible.[^8]


## Performance Issues

**Inefficient String Operations**

- `processChunk` creates multiple string conversions of the same data:[^2]

```go
data := string(chunk.Payload)  // Full conversion
// Later: bufio.NewReader(bytes.NewReader(chunk.Payload))
```

Work with `chunk.Payload` directly to avoid allocations.

**Unbounded Map Growth**

- The `connections` eBPF map has 10240 entries but no LRU eviction. In high-connection environments, this fills up quickly.[^3]
- Consider using `BPF_MAP_TYPE_LRU_HASH` instead.

**Missing Backpressure**

- No handling when ringbuffer fills up. The kernel will drop events silently. Add:[^2]
    - Ringbuffer size monitoring
    - Dropped event counter exposure
    - Alerting on drop rate

**Pod Watcher Lock Contention**

- Every event lookup acquires `watcher.mu` (RWMutex), but updates also need it. For read-heavy workloads, consider:[^5]
    - `sync.Map` for lock-free reads
    - Separate RWMutex for podMap vs serviceMap
    - Caching recently accessed IPs in a thread-local structure


## Code Quality \& Best Practices

**Error Handling**

- Many errors are logged but processing continues silently. Consider:[^2]
    - Metrics for error rates
    - Circuit breaker pattern for repeated failures
    - Exponential backoff on watch reconnections (partially implemented)

**Missing Context Propagation**

- The `cleanupLoop` in correlator doesn't accept context and runs forever. Should accept context and handle cancellation:[^4]

```go
func (c *Correlator) Start(ctx context.Context) {
    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()
    for {
        select {
        case <-ticker.C:
            c.cleanup()
        case <-ctx.Done():
            return
        }
    }
}
```

**Hardcoded Values**

- Magic numbers throughout: 30720, 10240, "10.42.0.1", 30 seconds. Move to configuration struct.[^9][^2][^3]

**Missing Observability**

- No metrics exposition (Prometheus format recommended)[^2]
- No health endpoints for Kubernetes probes
- No structured event counters (requests processed, filtered, errors)


## Go-Specific Improvements

**Use sync.Pool for Allocations**

```go
var eventPool = sync.Pool{
    New: func() interface{} {
        return &output.TraceEntry{}
    },
}
```

**Avoid Interface{} Boxing**

- Use generics (Go 1.18+) where appropriate instead of `interface{}`

**Connection Key Optimization**

- Your `ConnectionKey` struct uses strings for IPs. Use `[^4]byte` or `uint32` for faster comparison and less memory:[^4]

```go
type ConnectionKey struct {
    SrcIP   uint32
    SrcPort uint16
    DstIP   uint32
    DstPort uint16
}
```

**Missing Tests**

- No test files provided. Critical components like correlator, parser, and filter need unit tests.


## Kubernetes Best Practices

**Resource Limits**

- CPU limits of 500m may be insufficient for high-traffic clusters. Make this configurable via environment variables.[^7]

**Liveness/Readiness Probes**

- DaemonSet lacks health probes. Add endpoints to detect:[^7]
    - eBPF programs still attached
    - Ringbuffer operational
    - File writer functional

**Log Rotation**

- Writing to `/var/log/http-tracer/traces.log` without rotation will fill disk. Use:[^6][^7]
    - Log rotation sidecar
    - Or stream to stdout and let cluster logging handle it


## Recommended Fixes Priority

1. **HIGH**: Fix correlator race condition
2. **HIGH**: Reduce eBPF buffer sizes to pass verifier
3. **HIGH**: Implement proper HTTP stream reassembly
4. **MEDIUM**: Fix Pod watcher ResourceVersion handling
5. **MEDIUM**: Add sensitive data redaction
6. **MEDIUM**: Implement metrics and observability
7. **LOW**: Configuration externalization
8. **LOW**: Add comprehensive tests

Overall, this is a well-structured project with good separation of concerns. The main issues are around handling partial HTTP messages, race conditions, and production-readiness concerns. Great work on combining eBPF with Kubernetes metadata enrichment!
<span style="display:none">[^10][^11][^12]</span>

<div align="center">⁂</div>

[^1]: Makefile

[^2]: main.go

[^3]: http_tracer_full.bpf.c

[^4]: correlator.go

[^5]: watcher.go

[^6]: file_writer.go

[^7]: daemonset.yaml

[^8]: serviceaccount.yaml

[^9]: filter.go

[^10]: chunk.go

[^11]: event.go

[^12]: debug.go
