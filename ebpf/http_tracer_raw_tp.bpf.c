// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define AF_INET 2
#define HTTP_METHOD_MAX_LEN 8
#define HTTP_PATH_MAX_LEN 128
#define MAX_BUFFER_SIZE 256

// Syscall numbers (x86_64)
#define __NR_sendto 44
#define __NR_sendmsg 46
#define __NR_write 1

// Event structure
struct http_event {
  __u64 timestamp;
  __u32 pid;
  __u32 tid;
  __u32 syscall_nr;
  __u8 method[HTTP_METHOD_MAX_LEN];
  __u8 path[HTTP_PATH_MAX_LEN];
  __u32 payload_size;
  __u8 is_request;
};

// Ring buffer
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} events SEC(".maps");

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

// Raw tracepoint for sys_enter
// This is more efficient than regular tracepoints
// Args: struct pt_regs *regs, long id
SEC("raw_tracepoint/sys_enter")
int raw_tp_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
  // ctx->args[0] = struct pt_regs *
  // ctx->args[1] = syscall number

  long syscall_nr = ctx->args[1];

  // Only interested in write/send syscalls
  if (syscall_nr != __NR_write && syscall_nr != __NR_sendto &&
      syscall_nr != __NR_sendmsg)
    return 0;

  struct pt_regs *regs = (struct pt_regs *)ctx->args[0];

  // For write: write(fd, buf, count)
  // For sendto: sendto(fd, buf, len, flags, dest_addr, addrlen)
  // For sendmsg: sendmsg(fd, msg, flags)

  void *buf_ptr = NULL;
  size_t buf_len = 0;

  if (syscall_nr == __NR_write) {
    // write(fd, buf, count)
    buf_ptr = (void *)PT_REGS_PARM2(regs);
    buf_len = (size_t)PT_REGS_PARM3(regs);
  } else if (syscall_nr == __NR_sendto) {
    // sendto(fd, buf, len, flags, dest_addr, addrlen)
    buf_ptr = (void *)PT_REGS_PARM2(regs);
    buf_len = (size_t)PT_REGS_PARM3(regs);
  } else {
    // sendmsg is more complex, skip for this example
    return 0;
  }

  if (!buf_ptr || buf_len < 4)
    return 0;

  __u32 key = 0;
  char *buffer = bpf_map_lookup_elem(&temp_buffer, &key);
  if (!buffer)
    return 0;

  size_t to_read = buf_len < MAX_BUFFER_SIZE ? buf_len : MAX_BUFFER_SIZE;

  // Read from user space
  if (bpf_probe_read_user(buffer, to_read, buf_ptr) < 0)
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
  e->syscall_nr = syscall_nr;
  e->payload_size = buf_len;

  __builtin_memset(e->method, 0, HTTP_METHOD_MAX_LEN);
  __builtin_memset(e->path, 0, HTTP_PATH_MAX_LEN);

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
