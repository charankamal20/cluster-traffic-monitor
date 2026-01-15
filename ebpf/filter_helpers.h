#ifndef __FILTER_HELPERS_H
#define __FILTER_HELPERS_H

// Address families
#define AF_INET6 10

// Protocol detection constants
#define MIN_HTTP_SIZE 16

// HTTP Methods (first 4 bytes as integers for fast comparison)
#define GET_INT 0x20544547  // "GET "
#define POST_INT 0x54534F50 // "POST"
#define PUT_INT 0x20545550  // "PUT "
#define DEL_INT 0x454C4544  // "DEL" (DELETE)
#define HTTP_INT 0x50545448 // "HTTP"
#define HEAD_INT 0x44414548 // "HEAD"
#define PATC_INT 0x43544150 // "PATC" (PATCH)

// Health check detection
static __always_inline int is_http_traffic(const char *buf, __u32 len) {
  if (len < MIN_HTTP_SIZE) {
    return 0;
  }

  // Read first 4 bytes as integer for fast comparison
  __u32 first_word = 0;
  bpf_probe_read_kernel(&first_word, 4, buf);

  // Check HTTP methods
  if (first_word == GET_INT || first_word == POST_INT ||
      first_word == PUT_INT || first_word == DEL_INT ||
      first_word == HEAD_INT || first_word == PATC_INT) {
    return 1;
  }

  // Check HTTP response
  if (first_word == HTTP_INT) {
    return 1;
  }

  return 0;
}

static __always_inline int is_health_check(const char *buf, __u32 len) {
  if (len < 16) {
    return 0;
  }

  // Quick check for common health check patterns
  char path[16] = {0};
  bpf_probe_read_kernel(path, 16, buf);

  // Check for GET requests with health check paths
  if (path[0] == 'G' && path[1] == 'E' && path[2] == 'T') {
    // Check path after "GET "
    if (path[4] == '/' && path[5] == 'h' && path[6] == 'e') {
      return 1; // "/health*"
    }
    if (path[4] == '/' && path[5] == 'r' && path[6] == 'e') {
      return 1; // "/readyz"
    }
    if (path[4] == '/' && path[5] == 'l' && path[6] == 'i') {
      return 1; // "/livez"
    }
    if (path[4] == '/' && path[5] == 'm' && path[6] == 'e') {
      return 1; // "/metrics"
    }
  }

  return 0;
}

static __always_inline int should_trace_port(__u16 port) {
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
    return 0;
  default:
    return 1;
  }
}

#endif
