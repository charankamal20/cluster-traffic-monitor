//go:build ignore

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <sys/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define HTTP_METHOD_MAX_LEN 8
#define HTTP_PATH_MAX_LEN 128
#define HTTP_HOST_MAX_LEN 64
#define MAX_BUFFER_SIZE 256

// Minimal sock structure
struct sock_common {
    unsigned short skc_family;
    unsigned short skc_num;
    __be32 skc_daddr;
    __be32 skc_rcv_saddr;
    __be16 skc_dport;
};

struct sock {
    struct sock_common __sk_common;
};

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
    // Check for HTTP methods (first 4 bytes)
    if ((buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T' && buf[3] == ' ') ||
        (buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'S' && buf[3] == 'T') ||
        (buf[0] == 'P' && buf[1] == 'U' && buf[2] == 'T' && buf[3] == ' ') ||
        (buf[0] == 'H' && buf[1] == 'E' && buf[2] == 'A' && buf[3] == 'D') ||
        (buf[0] == 'D' && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'E')) {
        return 1;
    }
    // Check for HTTP response
    if (buf[0] == 'H' && buf[1] == 'T' && buf[2] == 'T' && buf[3] == 'P') {
        return 2;
    }
    return 0;
}

// Extract method (simplified - just copy first word)
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

// Extract path (simplified)
static __always_inline void extract_path(const char *buf, __u8 *path) {
    int start = 0;
    
    // Find first space
    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if (buf[i] == ' ') {
            start = i + 1;
            break;
        }
    }
    
    // Copy path
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

SEC("kprobe/tcp_sendmsg")
int kprobe_tcp_sendmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    void *msg_ptr = (void *)PT_REGS_PARM2(ctx);
    size_t size = (size_t)PT_REGS_PARM3(ctx);
    
    if (!sk || !msg_ptr)
        return 0;
    
    // Check family
    __u16 family;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != AF_INET)
        return 0;
    
    // Read connection info
    __u32 src_ip, dst_ip;
    __u16 src_port, dst_port;
    
    bpf_probe_read_kernel(&src_ip, sizeof(src_ip), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&dst_ip, sizeof(dst_ip), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&src_port, sizeof(src_port), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dst_port, sizeof(dst_port), &sk->__sk_common.skc_dport);
    
    dst_port = bpf_ntohs(dst_port);
    
    // Quick port filter - only common HTTP ports
    if (dst_port != 80 && dst_port != 8080 && dst_port != 8000 && 
        dst_port != 3000 && dst_port != 5000 && dst_port != 443)
        return 0;
    
    // Get iov_iter pointer (offset varies, but typically around 0x10-0x18)
    void *iov_iter_ptr;
    bpf_probe_read_kernel(&iov_iter_ptr, sizeof(iov_iter_ptr), msg_ptr + 0x10);
    
    // Get iovec pointer from iov_iter (first pointer in the struct)
    void *iovec_ptr;
    bpf_probe_read_kernel(&iovec_ptr, sizeof(iovec_ptr), iov_iter_ptr + 0x8);
    
    if (!iovec_ptr)
        return 0;
    
    // Read iovec base and len
    void *iov_base;
    size_t iov_len;
    bpf_probe_read_kernel(&iov_base, sizeof(iov_base), iovec_ptr);
    bpf_probe_read_kernel(&iov_len, sizeof(iov_len), iovec_ptr + 8);
    
    if (!iov_base || iov_len < 4)
        return 0;
    
    // Get buffer
    __u32 key = 0;
    char *buffer = bpf_map_lookup_elem(&temp_buffer, &key);
    if (!buffer)
        return 0;
    
    // Read data
    size_t to_read = iov_len < MAX_BUFFER_SIZE ? iov_len : MAX_BUFFER_SIZE;
    if (bpf_probe_read_user(buffer, to_read, iov_base) < 0)
        return 0;
    
    // Check if HTTP
    int http_type = is_http(buffer);
    if (http_type == 0)
        return 0;
    
    // Create event
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
    
    // Clear fields
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

