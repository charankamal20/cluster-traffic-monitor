// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define AF_INET 2

// Minimal event structure
struct debug_event {
  __u64 timestamp;
  __u32 pid;
  __u16 dst_port;
  __u8 iter_type;
  __u32 count;
};

// Ring buffer
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("kprobe/tcp_sendmsg")
int kprobe_tcp_sendmsg(struct pt_regs *ctx) {
  struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
  struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);

  if (!sk || !msg)
    return 0;

  // Check family
  __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
  if (family != AF_INET)
    return 0;

  // Read port
  __u16 dst_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

  // Get iter info
  struct iov_iter *iter = (struct iov_iter *)&msg->msg_iter;
  __u8 iter_type = BPF_CORE_READ(iter, iter_type);
  __u32 count = BPF_CORE_READ(iter, count);

  // Log EVERY tcp_sendmsg call
  struct debug_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e)
    return 0;

  e->timestamp = bpf_ktime_get_ns();
  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->dst_port = dst_port;
  e->iter_type = iter_type;
  e->count = count;

  bpf_ringbuf_submit(e, 0);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
