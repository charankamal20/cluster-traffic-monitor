// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define AF_INET 2
#define HTTP_METHOD_MAX_LEN 8
#define HTTP_PATH_MAX_LEN 128
#define HTTP_HOST_MAX_LEN 64
#define MAX_BUFFER_SIZE 256

// TCP states
#define TCP_ESTABLISHED 1
#define TCP_CLOSE 7

// Event structure
struct http_event {
  __u64 timestamp;
  __u32 pid;
  __u32 tid;
  __u32 src_ip;
  __u32 dst_ip;
  __u16 src_port;
  __u16 dst_port;
  __u8 method[HTTP_METHOD_MAX_LEN];
  __u8 path[HTTP_PATH_MAX_LEN];
  __u8 host[HTTP_HOST_MAX_LEN];
  __u32 payload_size;
  __u8 is_request;
};

// Connection tracking structure
struct conn_info {
  __u32 src_ip;
  __u32 dst_ip;
  __u16 src_port;
  __u16 dst_port;
  __u32 pid;
  __u32 tid;
};

// Ring buffer
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Connection tracking map
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, __u64); // socket pointer as key
  __type(value, struct conn_info);
} connections SEC(".maps");

// Per-CPU buffer
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, char[MAX_BUFFER_SIZE]);
} temp_buffer SEC(".maps");

// Simple HTTP detection
static __always_inline int is_http(const char *buf) {
  if ((buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T' && buf[3] == ' ') ||
      (buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'S' && buf[3] == 'T') ||
      (buf[0] == 'P' && buf[1] == 'U' && buf[2] == 'T' && buf[3] == ' ') ||
      (buf[0] == 'H' && buf[1] == 'E' && buf[2] == 'A' && buf[3] == 'D') ||
      (buf[0] == 'D' && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'E')) {
    return 1;
  }
  if (buf[0] == 'H' && buf[1] == 'T' && buf[2] == 'T' && buf[3] == 'P') {
    return 2;
  }
  return 0;
}

static __always_inline void extract_method(const char *buf, __u8 *method) {
#pragma unroll
  for (int i = 0; i < 7; i++) {
    if (buf[i] == ' ') {
      method[i] = '\0';
      return;
    }
    method[i] = buf[i];
  }
  method[7] = '\0';
}

static __always_inline void extract_path(const char *buf, __u8 *path) {
  int start = 0;
#pragma unroll
  for (int i = 0; i < 10; i++) {
    if (buf[i] == ' ') {
      start = i + 1;
      break;
    }
  }
#pragma unroll
  for (int i = 0; i < 64; i++) {
    char c = buf[start + i];
    if (c == ' ' || c == '?' || c == '\r' || c == '\n') {
      path[i] = '\0';
      return;
    }
    path[i] = c;
  }
  path[64] = '\0';
}

// Tracepoint: sock:inet_sock_set_state
// This tracepoint fires when TCP connection state changes
SEC("tracepoint/sock/inet_sock_set_state")
int trace_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {
  // Only track IPv4
  if (ctx->family != AF_INET)
    return 0;

  // Track established connections
  if (ctx->newstate == TCP_ESTABLISHED) {
    __u64 sock_ptr = (__u64)ctx;
    struct conn_info info = {};

    // Copy IPv4 addresses (first 4 bytes)
    __builtin_memcpy(&info.src_ip, ctx->saddr, 4);
    __builtin_memcpy(&info.dst_ip, ctx->daddr, 4);
    info.src_port = ctx->sport;
    info.dst_port = ctx->dport;
    info.pid = bpf_get_current_pid_tgid() >> 32;
    info.tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    bpf_map_update_elem(&connections, &sock_ptr, &info, BPF_ANY);
  }
  // Clean up closed connections
  else if (ctx->newstate == TCP_CLOSE) {
    __u64 sock_ptr = (__u64)ctx;
    bpf_map_delete_elem(&connections, &sock_ptr);
  }

  return 0;
}

// Still use kprobe for tcp_sendmsg to capture actual data
// Tracepoints don't give us access to the message buffer
SEC("kprobe/tcp_sendmsg")
int kprobe_tcp_sendmsg(struct pt_regs *ctx) {
  struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
  struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
  size_t size = (size_t)PT_REGS_PARM3(ctx);

  if (!sk || !msg)
    return 0;

  // Check family safely
  __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
  if (family != AF_INET)
    return 0;

  // Read connection info with CO-RE
  __u32 src_ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
  __u32 dst_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
  __u16 src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
  __u16 dst_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

  // Handle user data from msghdr
  struct iov_iter *iter = (struct iov_iter *)&msg->msg_iter;

  void *iov_base = NULL;
  size_t iov_len = 0;

  // Check iterator type
  __u8 iter_type = BPF_CORE_READ(iter, iter_type);

  // Try to get count which should be total bytes
  size_t count = BPF_CORE_READ(iter, count);

  if (count == 0 || count < 4)
    return 0;

  // ITER_UBUF = 0 (single buffer, most common for sends)
  // ITER_IOVEC = 1 (array of buffers)
  if (iter_type == 0) {
    // ITER_UBUF case - read from __ubuf_iovec
    struct iovec ubuf;
    BPF_CORE_READ_INTO(&ubuf, iter, __ubuf_iovec);
    iov_base = ubuf.iov_base;
    iov_len = ubuf.iov_len;
  } else if (iter_type == 1) {
    // ITER_IOVEC case - read from __iov pointer
    const struct iovec *iov_ptr;
    iov_ptr = BPF_CORE_READ(iter, __iov);

    if (!iov_ptr)
      return 0;

    iov_base = BPF_CORE_READ(iov_ptr, iov_base);
    iov_len = BPF_CORE_READ(iov_ptr, iov_len);
  } else if (iter_type == 3) {
    // ITER_KVEC = 3 (kernel buffers) - try this too
    const struct kvec *kvec_ptr;
    kvec_ptr = BPF_CORE_READ(iter, kvec);

    if (!kvec_ptr)
      return 0;

    // kvec has iov_base and iov_len like iovec
    iov_base = BPF_CORE_READ(kvec_ptr, iov_base);
    iov_len = BPF_CORE_READ(kvec_ptr, iov_len);
  } else {
    // Other iterator types - skip for now
    return 0;
  }

  if (!iov_base || iov_len < 4)
    return 0;

  __u32 key = 0;
  char *buffer = bpf_map_lookup_elem(&temp_buffer, &key);
  if (!buffer)
    return 0;

  size_t to_read = iov_len < MAX_BUFFER_SIZE ? iov_len : MAX_BUFFER_SIZE;

  // Try kernel read first for KVEC, user read for others
  int read_result;
  if (iter_type == 3) {
    read_result = bpf_probe_read_kernel(buffer, to_read, iov_base);
  } else {
    read_result = bpf_probe_read_user(buffer, to_read, iov_base);
  }

  if (read_result < 0)
    return 0;

  int http_type = is_http(buffer);
  if (http_type == 0)
    return 0;

  struct http_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e)
    return 0;

  e->timestamp = bpf_ktime_get_ns();
  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  e->src_ip = src_ip;
  e->dst_ip = dst_ip;
  e->src_port = src_port;
  e->dst_port = dst_port;
  e->payload_size = size;

  __builtin_memset(e->method, 0, HTTP_METHOD_MAX_LEN);
  __builtin_memset(e->path, 0, HTTP_PATH_MAX_LEN);
  __builtin_memset(e->host, 0, HTTP_HOST_MAX_LEN);

  if (http_type == 1) {
    e->is_request = 1;
    extract_method(buffer, e->method);
    extract_path(buffer, e->path);
  } else {
    e->is_request = 0;
    __builtin_memcpy(e->method, "RESPONSE", 8);
  }

  bpf_ringbuf_submit(e, 0);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
