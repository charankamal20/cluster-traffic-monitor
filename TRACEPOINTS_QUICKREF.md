# Quick Reference: Tracepoints for HTTP Monitoring

## TL;DR

**For your HTTP tracer**: Use a **hybrid approach**
- ✅ Tracepoint for connection tracking (stable)
- ✅ Kprobe for HTTP data access (flexible)

## Three Implementation Options

### 1. Hybrid (Recommended)
**File**: `http_tracer_tracepoint.bpf.c`
- Uses `sock:inet_sock_set_state` tracepoint
- Plus `tcp_sendmsg` kprobe for data
- Best balance of stability and functionality

### 2. Raw Tracepoint (High Performance)
**File**: `http_tracer_raw_tp.bpf.c`
- Uses `raw_tracepoint/sys_enter`
- Lower overhead, catches all syscalls
- Requires more filtering

### 3. Pure Kprobe (Current)
**File**: `http_tracer.bpf.c`
- Your current implementation
- Most flexible but less stable

## Why Your Current Code Might Not Work

The `iov_iter` structure changed in kernel 5.14+:
```c
// This may fail on newer kernels
__u8 iter_type = BPF_CORE_READ(iter, iter_type);
```

## Quick Debug Commands

```bash
# Check if kprobe is attached
sudo cat /sys/kernel/debug/tracing/kprobe_events

# See live events
sudo cat /sys/kernel/debug/tracing/trace_pipe

# List TCP tracepoints
sudo cat /sys/kernel/debug/tracing/available_events | grep tcp
```

## KubeArmor Insights

- Focuses on **syscall monitoring**, not L7 protocols
- Uses tracepoints for stability
- Monitors: `socket()`, `connect()`, `bind()`, `listen()`
- **Does NOT** parse HTTP or application protocols

## Useful Network Tracepoints

| Tracepoint | What it tracks |
|------------|----------------|
| `sock:inet_sock_set_state` | TCP connection state changes |
| `tcp:tcp_retransmit_skb` | Packet retransmissions |
| `net:netif_receive_skb` | Incoming packets |
| `skb:skb_copy_datagram_iovec` | Data to userspace |

## Next Steps

1. Try the hybrid approach first
2. If that doesn't work, check kernel version compatibility
3. Consider using socket filters as alternative

See [tracepoints_guide.md](file:///home/classikh/.gemini/antigravity/brain/830fe0bb-5801-4771-8dff-6227844fb74b/tracepoints_guide.md) for full details.
