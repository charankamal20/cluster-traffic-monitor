// go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "filter_helpers.h"

#define AF_INET 2
#define AF_INET6 10
#define MAX_DATA_SIZE 8192 // Increased for HTTP/2 frames
#define MAX_BUFFER_SIZE 8192

// Direction
#define DIR_EGRESS 0
#define DIR_INGRESS 1

// TCP states
#define TCP_ESTABLISHED 1
#define TCP_CLOSE 7

// Protocol detection
#define PROTO_UNKNOWN 0
#define PROTO_HTTP1 1
#define PROTO_HTTP2 2
#define PROTO_GRPC 3

// HTTP/2 Frame Types
#define HTTP2_FRAME_DATA 0x00
#define HTTP2_FRAME_HEADERS 0x01
#define HTTP2_FRAME_SETTINGS 0x04
#define HTTP2_FRAME_PING 0x06
#define HTTP2_FRAME_GOAWAY 0x07

// Data Chunk Event
struct data_event {
  __u64 timestamp;
  __u32 pid;
  __u32 tid;
  __u32 src_ip;
  __u32 dst_ip;
  __u16 src_port;
  __u16 dst_port;
  __u32 data_len;
  __u8 direction;
  __u8 protocol;
  __u8 flags; // Additional flags (e.g., frame end for HTTP/2)
  __u8 _pad[5];
  __u64 sock_ptr;
  unsigned char payload[MAX_DATA_SIZE];
};

// Connection info for tracking
struct conn_info {
  __u32 src_ip;
  __u32 dst_ip;
  __u16 src_port;
  __u16 dst_port;
  __u8 protocol;
  __u8 http2_detected; // Set to 1 after HTTP/2 preface seen
};

// Ring buffer for data events
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1024 * 1024); // 1MB for high throughput
} events SEC(".maps");

// Active Connections Map
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 65536); // Increased for production
  __type(key, __u64);
  __type(value, struct conn_info);
} connections SEC(".maps");

// Connection filter cache
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 65536);
  __type(key, __u64);
  __type(value, __u8);
} connection_filter_cache SEC(".maps");

// Per-CPU scratch buffer
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct data_event);
} event_scratch SEC(".maps");

// Statistics map for monitoring
struct stats {
  __u64 total_packets;
  __u64 http1_packets;
  __u64 http2_packets;
  __u64 grpc_packets;
  __u64 filtered_packets;
  __u64 parse_errors;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct stats);
} stats_map SEC(".maps");

// Tracepoint context structure
struct inet_sock_set_state_args {
  __u64 pad;
  const void *skaddr;
  int oldstate;
  int newstate;
  __u16 sport;
  __u16 dport;
  __u16 family;
  __u16 protocol;
  __u8 saddr[4];
  __u8 daddr[4];
  __u8 saddr_v6[16];
  __u8 daddr_v6[16];
};

// --- Protocol Detection Helpers ---

// HTTP/2 Connection Preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
static __always_inline int is_http2_preface(const unsigned char *buf,
                                            __u32 len) {
  if (len < 24) {
    return 0;
  }

  // Check signature bytes efficiently
  __u64 sig1, sig2, sig3;
  bpf_probe_read_kernel(&sig1, 8, buf);
  bpf_probe_read_kernel(&sig2, 8, buf + 8);
  bpf_probe_read_kernel(&sig3, 8, buf + 16);

  // "PRI * HT" = 0x5448202A20495250
  // "TP/2.0\r\n" = 0x0A0D302E322F5054
  // "\r\nSM\r\n\r\n" = 0x0A0D0A0D4D530A0D

  if (sig1 == 0x5448202A20495250ULL && sig2 == 0x0A0D302E322F5054ULL &&
      sig3 == 0x0A0D0A0D4D530A0DULL) {
    return 1;
  }

  return 0;
}

// Validate HTTP/2 frame header
static __always_inline int is_valid_http2_frame(const unsigned char *buf,
                                                __u32 len) {
  if (len < 9) {
    return 0;
  }

  // Extract frame header fields
  __u32 frame_length = (buf[0] << 16) | (buf[1] << 8) | buf[2];
  __u8 frame_type = buf[3];
  __u8 flags = buf[4];

  // Validate frame length (max 16KB standard, 16MB extended)
  if (frame_length > 16777215) { // 2^24 - 1
    return 0;
  }

  // Validate frame type (0-9 are defined)
  if (frame_type > 9) {
    return 0;
  }

  // Stream ID is at bytes 5-8 (31 bits, ignore reserved bit)
  __u32 stream_id;
  bpf_probe_read_kernel(&stream_id, 4, buf + 5);
  stream_id = bpf_ntohl(stream_id) & 0x7FFFFFFF;

  // SETTINGS and PING must use stream 0
  if ((frame_type == HTTP2_FRAME_SETTINGS || frame_type == HTTP2_FRAME_PING) &&
      stream_id != 0) {
    return 0;
  }

  // DATA and HEADERS must use stream > 0
  if ((frame_type == HTTP2_FRAME_DATA || frame_type == HTTP2_FRAME_HEADERS) &&
      stream_id == 0) {
    return 0;
  }

  return 1;
}

// Detect gRPC by checking for HEADERS frame with specific patterns
static __always_inline int is_grpc_headers_frame(const unsigned char *buf,
                                                 __u32 len) {
  if (!is_valid_http2_frame(buf, len)) {
    return 0;
  }

  __u8 frame_type = buf[3];
  if (frame_type != HTTP2_FRAME_HEADERS) {
    return 0;
  }

  // gRPC uses specific HPACK patterns
  // This is heuristic - look for common gRPC header patterns in payload
  if (len > 20) {
// Look for "application/grpc" in HPACK encoded headers
// This is a simplified check - full HPACK decoding is in userspace
#pragma unroll
    for (int i = 9; i < len - 10 && i < 100; i++) {
      if (buf[i] == 'g' && buf[i + 1] == 'r' && buf[i + 2] == 'p' &&
          buf[i + 3] == 'c') {
        return 1;
      }
    }
  }

  return 0;
}

// Comprehensive protocol detection with state tracking
static __always_inline __u8 detect_protocol(const unsigned char *buf, __u32 len,
                                            struct conn_info *conn) {
  // Check if we already detected HTTP/2 for this connection
  if (conn->http2_detected) {
    if (is_grpc_headers_frame(buf, len)) {
      return PROTO_GRPC;
    }
    if (is_valid_http2_frame(buf, len)) {
      return PROTO_HTTP2;
    }
  }

  // Check for HTTP/2 preface (connection establishment)
  if (is_http2_preface(buf, len)) {
    conn->http2_detected = 1;
    return PROTO_HTTP2;
  }

  // Check for HTTP/2 frame
  if (is_valid_http2_frame(buf, len)) {
    conn->http2_detected = 1;

    // Check if it's gRPC
    if (is_grpc_headers_frame(buf, len)) {
      return PROTO_GRPC;
    }
    return PROTO_HTTP2;
  }

  // Check for HTTP/1.x
  if (is_http_traffic((const char *)buf, len)) {
    return PROTO_HTTP1;
  }

  return PROTO_UNKNOWN;
}

// Update statistics
static __always_inline void update_stats(__u8 protocol, int filtered) {
  __u32 key = 0;
  struct stats *s = bpf_map_lookup_elem(&stats_map, &key);
  if (!s) {
    return;
  }

  __sync_fetch_and_add(&s->total_packets, 1);

  if (filtered) {
    __sync_fetch_and_add(&s->filtered_packets, 1);
    return;
  }

  switch (protocol) {
  case PROTO_HTTP1:
    __sync_fetch_and_add(&s->http1_packets, 1);
    break;
  case PROTO_HTTP2:
    __sync_fetch_and_add(&s->http2_packets, 1);
    break;
  case PROTO_GRPC:
    __sync_fetch_and_add(&s->grpc_packets, 1);
    break;
  }
}

// --- Hooks ---

// 1. Connection Tracking
SEC("tracepoint/sock/inet_sock_set_state")
int trace_inet_sock_set_state(struct inet_sock_set_state_args *ctx) {
  if (ctx->family != AF_INET && ctx->family != AF_INET6) {
    return 0;
  }

  __u64 sock_ptr = (__u64)ctx->skaddr;

  if (ctx->newstate == TCP_ESTABLISHED) {
    struct conn_info info = {0};

    if (ctx->family == AF_INET6) {
      __u8 s6[16];
      __u8 d6[16];
      unsigned long ctx_addr = (unsigned long)ctx;
      bpf_probe_read(s6, 16, (void *)(ctx_addr + 40));
      bpf_probe_read(d6, 16, (void *)(ctx_addr + 56));

      // Check for IPv4-mapped addresses
      int is_v4_mapped = 1;
#pragma unroll
      for (int i = 0; i < 10; i++) {
        if (s6[i] != 0 || d6[i] != 0) {
          is_v4_mapped = 0;
          break;
        }
      }

      if (is_v4_mapped && s6[10] == 0xff && s6[11] == 0xff) {
        __builtin_memcpy(&info.src_ip, &s6[12], 4);
        __builtin_memcpy(&info.dst_ip, &d6[12], 4);
      } else {
        return 0; // Pure IPv6 not supported yet
      }
    } else {
      __builtin_memcpy(&info.src_ip, ctx->saddr, 4);
      __builtin_memcpy(&info.dst_ip, ctx->daddr, 4);
    }

    info.src_port = ctx->sport;
    info.dst_port = ctx->dport;
    info.protocol = PROTO_UNKNOWN;
    info.http2_detected = 0;

    bpf_map_update_elem(&connections, &sock_ptr, &info, BPF_ANY);

  } else if (ctx->newstate == TCP_CLOSE) {
    bpf_map_delete_elem(&connections, &sock_ptr);
    bpf_map_delete_elem(&connection_filter_cache, &sock_ptr);
  }

  return 0;
}

// 2. Egress Data Capture
SEC("kprobe/tcp_sendmsg")
int kprobe_tcp_sendmsg(struct pt_regs *ctx) {
  struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
  struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);

  if (!sk || !msg)
    return 0;

  __u64 sock_ptr = (__u64)sk;
  struct conn_info *conn = bpf_map_lookup_elem(&connections, &sock_ptr);
  if (!conn)
    return 0;

  // Use scratch buffer to avoid stack limit
  __u32 key = 0;
  struct data_event *e = bpf_map_lookup_elem(&event_scratch, &key);
  if (!e)
    return 0;

  // Fill metadata
  e->timestamp = bpf_ktime_get_ns();
  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  e->src_ip = conn->src_ip;
  e->dst_ip = conn->dst_ip;
  e->src_port = conn->src_port;
  e->dst_port = conn->dst_port;
  e->direction = DIR_EGRESS;
  e->sock_ptr = sock_ptr;
  e->flags = 0;

  // Read data from iov_iter
  struct iov_iter *iter = (struct iov_iter *)&msg->msg_iter;
  __u8 iter_type = BPF_CORE_READ(iter, iter_type);
  size_t len = BPF_CORE_READ(iter, count);

  if (len == 0)
    return 0;

  if (len > MAX_DATA_SIZE)
    len = MAX_DATA_SIZE;

  e->data_len = len;

  void *iov_base = NULL;
  size_t iov_offset = 0;

  if (iter_type == 0) { // ITER_UBUF
    void *ubuf = (void *)BPF_CORE_READ(iter, ubuf);
    iov_base = ubuf;
    iov_offset = BPF_CORE_READ(iter, iov_offset);
  } else if (iter_type == 1) { // ITER_IOVEC
    const struct iovec *iov_ptr = BPF_CORE_READ(iter, __iov);
    if (iov_ptr) {
      iov_base = BPF_CORE_READ(iov_ptr, iov_base);
      iov_offset = BPF_CORE_READ(iter, iov_offset);
    }
  } else {
    return 0;
  }

  if (!iov_base)
    return 0;

  // Read payload
  long ret = bpf_probe_read_user(e->payload, len, iov_base + iov_offset);
  if (ret < 0) {
    return 0; // Failed to read user memory
  }

  // Detect protocol
  e->protocol = detect_protocol(e->payload, len, conn);

  // Update connection protocol if detected
  if (e->protocol != PROTO_UNKNOWN && conn->protocol == PROTO_UNKNOWN) {
    conn->protocol = e->protocol;
  }

  // Check filter cache
  __u8 *cached_decision =
      bpf_map_lookup_elem(&connection_filter_cache, &sock_ptr);
  if (cached_decision) {
    if (*cached_decision == 0) {
      update_stats(e->protocol, 1);
      return 0;
    }
    goto send_event;
  }

  // First packet filtering
  __u8 decision = 1;

  // Filter 1: Address family
  __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
  if (family != AF_INET && family != AF_INET6) {
    decision = 0;
  }

  // Filter 2: Port filtering
  if (decision && !should_trace_port(conn->dst_port)) {
    decision = 0;
  }

  // Filter 3: Protocol must be detected
  if (decision && e->protocol == PROTO_UNKNOWN) {
    decision = 0;
  }

  // Filter 4: Health checks for HTTP/1.x only
  if (decision && e->protocol == PROTO_HTTP1) {
    if (is_health_check((const char *)e->payload, len)) {
      decision = 0;
    }
  }

  // Cache the decision
  bpf_map_update_elem(&connection_filter_cache, &sock_ptr, &decision, BPF_ANY);

  if (decision == 0) {
    update_stats(e->protocol, 1);
    return 0;
  }

send_event:
  update_stats(e->protocol, 0);

  // Use dynamic sizing for efficiency
  bpf_ringbuf_output(&events, e, sizeof(*e) - MAX_DATA_SIZE + len, 0);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
