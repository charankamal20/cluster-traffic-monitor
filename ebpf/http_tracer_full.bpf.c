// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Include filter helpers AFTER BPF headers so types are defined
#include "filter_helpers.h"

#define AF_INET 2
#define MAX_DATA_SIZE 4096
#define MAX_BUFFER_SIZE 4096

// Direction
#define DIR_EGRESS 0
#define DIR_INGRESS 1

// TCP states
#define TCP_ESTABLISHED 1
#define TCP_CLOSE 7

// Data Chunk Event
// Sends raw TCP payload to userspace for reassembly
struct data_event {
  __u64 timestamp;
  __u32 pid;
  __u32 tid;
  __u32 src_ip;
  __u32 dst_ip;
  __u16 src_port;
  __u16 dst_port;
  __u32 data_len;
  __u8 direction; // 0=Egress, 1=Ingress
  __u8 _pad[7];
  __u64 sock_ptr;
  unsigned char payload[MAX_DATA_SIZE];
};

// Connection info for tracking
struct conn_info {
  __u32 src_ip;
  __u32 dst_ip;
  __u16 src_port;
  __u16 dst_port;
};

// Ring buffer for data events
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024); // Increase size for full data
} events SEC(".maps");

// Active Connections Map (LRU for automatic eviction)
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 10240);
  __type(key, __u64); // socket pointer
  __type(value, struct conn_info);
} connections SEC(".maps");

// Connection filter cache (0=block, 1=allow)
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 10240);
  __type(key, __u64);  // socket pointer
  __type(value, __u8); // filter decision
} connection_filter_cache SEC(".maps");

// Per-CPU scratch buffer to avoid stack limit
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct data_event);
} event_scratch SEC(".maps");

// Tracepoint context structure for sock:inet_sock_set_state
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

// --- Helpers ---

static __always_inline void fill_connection_info(struct conn_info *info,
                                                 struct sock *sk) {
  info->src_ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
  info->dst_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
  info->src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
  info->dst_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
}

// --- Hooks ---

// 1. Connection Tracking (tracepoint)
SEC("tracepoint/sock/inet_sock_set_state")
int trace_inet_sock_set_state(struct inet_sock_set_state_args *ctx) {
  if (ctx->family != AF_INET)
    return 0;

  __u64 sock_ptr = (__u64)ctx->skaddr;

  if (ctx->newstate == TCP_ESTABLISHED) {
    struct conn_info info = {};
    __builtin_memcpy(&info.src_ip, ctx->saddr, 4);
    __builtin_memcpy(&info.dst_ip, ctx->daddr, 4);
    info.src_port = ctx->sport;
    info.dst_port = ctx->dport;
    bpf_map_update_elem(&connections, &sock_ptr, &info, BPF_ANY);
  } else if (ctx->newstate == TCP_CLOSE) {
    bpf_map_delete_elem(&connections, &sock_ptr);
  }
  return 0;
}

// 2. Egress Data (kprobe/tcp_sendmsg)
// Capture data sent by the application
SEC("kprobe/tcp_sendmsg")
int kprobe_tcp_sendmsg(struct pt_regs *ctx) {
  struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
  struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
  if (!sk || !msg)
    return 0;

  // Check if we are tracking this connection
  __u64 sock_ptr = (__u64)sk;
  struct conn_info *conn = bpf_map_lookup_elem(&connections, &sock_ptr);
  if (!conn)
    return 0;

  // Prepare event from scratch buffer
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
  e->sock_ptr = sock_ptr; // ⭐ ADD THIS LINE

  // Read data
  struct iov_iter *iter = (struct iov_iter *)&msg->msg_iter;
  __u8 iter_type = BPF_CORE_READ(iter, iter_type);
  size_t len = BPF_CORE_READ(iter, count);

  if (len == 0)
    return 0;

  // Cap length
  if (len > MAX_DATA_SIZE)
    len = MAX_DATA_SIZE;
  e->data_len = len;

  // Read payload based on iter type
  // Note: Simplified reading logic, assuming most common cases for simplicity
  void *iov_base = NULL;
  if (iter_type == 0) { // ITER_UBUF
    // Simplified reading: if ITER_UBUF, the "iov_base" is technically just the
    // "ubuf" pointer. In newer kernels, iov_iter has a union with "ubuf". We
    // will use BPF_CORE_READ which handles the offset automatically if the
    // field exists. Ensure we handle the "iov_offset" which is how much has
    // already been read.
    void *ubuf = (void *)BPF_CORE_READ(iter, ubuf);
    iov_base = ubuf;
    size_t iov_offset = BPF_CORE_READ(iter, iov_offset);
    bpf_probe_read_user(e->payload, len, iov_base + iov_offset);
  } else if (iter_type == 1) { // ITER_IOVEC
    const struct iovec *iov_ptr = BPF_CORE_READ(iter, __iov);
    if (iov_ptr) {
      iov_base = BPF_CORE_READ(iov_ptr, iov_base);
      size_t iov_offset = BPF_CORE_READ(iter, iov_offset);
      bpf_probe_read_user(e->payload, len, iov_base + iov_offset);
    }
  } else {
    return 0; // Unsupported for now
  }

  // ============ FILTERING STAGES ============

  // Check filter cache first
  __u8 *cached_decision =
      bpf_map_lookup_elem(&connection_filter_cache, &sock_ptr);
  if (cached_decision) {
    if (*cached_decision == 0) {
      return 0; // Previously filtered
    }
    // Skip re-filtering, send immediately
    goto send_event;
  }

  // First packet on this connection: do full filtering
  __u8 decision = 1; // default: allow

  // Filter 1: Address family (already checked in tracepoint)
  __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
  if (family != AF_INET && family != AF_INET6) {
    decision = 0;
  }

  // Filter 2: Port filtering
  if (decision && !should_trace_port(conn->dst_port)) {
    decision = 0;
  }

  // Filter 3: Protocol detection
  if (decision && !is_http_traffic((const char *)e->payload, len)) {
    decision = 0;
  }

  // Filter 4: Health check filtering
  if (decision && is_health_check((const char *)e->payload, len)) {
    decision = 0;
  }

  // Cache the decision
  bpf_map_update_elem(&connection_filter_cache, &sock_ptr, &decision, BPF_ANY);

  if (decision == 0) {
    return 0;
  }

send_event:
  // Use dynamic sizing to avoid sending unused buffer space
  // Use local 'len' because verifier knows its bounds (checked above)
  bpf_ringbuf_output(&events, e, sizeof(*e) - MAX_DATA_SIZE + len, 0);
  return 0;
}

// 3. Ingress Data (kprobe/tcp_recvmsg)
// Capture data received by the application (on return from syscall)
// We use kretprobe usually to get the actual bytes read, or we can use
// tracepoint if available. For simplicity and data access, we'll use kprobe
// entry to get the socket, and maybe a retprobe is better. Actually, in
// tcp_recvmsg, the buffers are filled *after* the call. So
// kprobe/tcp_cleanup_rbuf is often used to see data that has been copied to
// user. Let's try `tcp_cleanup_rbuf` which is called after user reads data.

SEC("kprobe/tcp_cleanup_rbuf")
int kprobe_tcp_cleanup_rbuf(struct pt_regs *ctx) {
  struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
  int copied = (int)PT_REGS_PARM2(ctx);

  if (copied <= 0)
    return 0;
  if (!sk)
    return 0;

  __u64 sock_ptr = (__u64)sk;
  struct conn_info *conn = bpf_map_lookup_elem(&connections, &sock_ptr);
  if (!conn)
    return 0;

  // Using scratch buffer
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
  e->direction = DIR_INGRESS;
  e->sock_ptr = sock_ptr;
  // We can't easily get the user buffer pointer here in cleanup_rbuf.
  // However, cleanup_rbuf means the data is ACKed.
  // A better place for "what is being read" is kretprobe/tcp_recvmsg.
  return 0;
}

// Let's switch Ingress strategy: kretprobe/tcp_recvmsg
// We need to save the msghdr pointer from entry
struct recv_args {
  __u64 sk;
  __u64 iov_base;
  __u64 iov_offset;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, __u64); // tid
  __type(value, struct recv_args);
} active_recv SEC(".maps");

SEC("kprobe/tcp_recvmsg")
int kprobe_tcp_recvmsg(struct pt_regs *ctx) {
  __u64 tid = bpf_get_current_pid_tgid();
  struct recv_args args = {};
  args.sk = (__u64)PT_REGS_PARM1(ctx);

  struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
  struct iov_iter *iter = (struct iov_iter *)&msg->msg_iter;

  // Capture buffer address at entry
  __u8 iter_type = BPF_CORE_READ(iter, iter_type);
  void *iov_base = NULL;
  size_t iov_offset = 0;

  if (iter_type == 0) { // ITER_UBUF
    // Direct ubuf access
    iov_base = (void *)BPF_CORE_READ(iter, ubuf);
    iov_offset = BPF_CORE_READ(iter, iov_offset);
  } else if (iter_type == 1) { // ITER_IOVEC
    const struct iovec *iov_ptr = BPF_CORE_READ(iter, __iov);
    if (iov_ptr) {
      iov_base = BPF_CORE_READ(iov_ptr, iov_base);
      iov_offset = BPF_CORE_READ(iter, iov_offset);
    }
  }

  args.iov_base = (__u64)iov_base;
  args.iov_offset = (__u64)iov_offset;

  bpf_map_update_elem(&active_recv, &tid, &args, BPF_ANY);
  return 0;
}

SEC("kretprobe/tcp_recvmsg")
int kretprobe_tcp_recvmsg(struct pt_regs *ctx) {
  __u64 tid = bpf_get_current_pid_tgid();
  struct recv_args *args = bpf_map_lookup_elem(&active_recv, &tid);

  if (!args)
    return 0;

  int copied = PT_REGS_RC(ctx);
  if (copied <= 0) {
    bpf_map_delete_elem(&active_recv, &tid);
    return 0;
  }

  // Check connection tracking
  __u64 sock_ptr = args->sk;
  struct conn_info *conn = bpf_map_lookup_elem(&connections, &sock_ptr);
  if (!conn) {
    bpf_map_delete_elem(&active_recv, &tid);
    return 0;
  }

  // Scratch buffer
  __u32 key = 0;
  struct data_event *e = bpf_map_lookup_elem(&event_scratch, &key);
  if (!e) {
    bpf_map_delete_elem(&active_recv, &tid);
    return 0;
  }

  e->timestamp = bpf_ktime_get_ns();
  e->pid = tid >> 32;
  e->tid = tid & 0xFFFFFFFF;
  e->src_ip = conn->src_ip;
  e->dst_ip = conn->dst_ip;
  e->src_port = conn->src_port;
  e->dst_port = conn->dst_port;
  e->direction = DIR_INGRESS;
  e->sock_ptr = sock_ptr; // ⭐ ADD THIS LINE

  size_t len = copied;
  if (len > MAX_DATA_SIZE)
    len = MAX_DATA_SIZE;
  e->data_len = len;

  // Read from saved address
  void *iov_base = (void *)args->iov_base;
  size_t iov_offset = (size_t)args->iov_offset;

  if (iov_base) {
    bpf_probe_read_user(e->payload, len, iov_base + iov_offset);
  }

  // Use dynamic sizing
  bpf_ringbuf_output(&events, e, sizeof(*e) - MAX_DATA_SIZE + len, 0);
  bpf_map_delete_elem(&active_recv, &tid);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
