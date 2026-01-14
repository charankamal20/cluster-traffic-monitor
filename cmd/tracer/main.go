package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/charankamal20/cluster-traffic-monitor/internal/events"
	"github.com/charankamal20/cluster-traffic-monitor/internal/filter"
	"github.com/charankamal20/cluster-traffic-monitor/internal/k8s"
	"github.com/charankamal20/cluster-traffic-monitor/internal/output"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 bpf_full ../../ebpf/http_tracer_full.bpf.c -- -I/usr/include -I../../ebpf

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func run(ctx context.Context) error {
	// 1. Start K8s Watcher
	watcher, err := k8s.NewWatcher()
	if err != nil {
		log.Printf("Warning: Failed to create K8s watcher (running without enrichment): %v", err)
	} else {
		if err := watcher.Start(ctx); err != nil {
			log.Printf("Warning: Failed to start K8s watcher: %v", err)
		}
	}

	// 2. Remove resource limits
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock: %w", err)
	}

	// 3. Load eBPF objects
	objs := bpf_fullObjects{}
	if err := loadBpf_fullObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading eBPF objects: %w", err)
	}
	defer objs.Close()
	log.Println("✓ eBPF objects loaded successfully")

	// 4. Attach Hooks
	// Tracepoint for connection tracking
	tp, err := link.Tracepoint("sock", "inet_sock_set_state", objs.TraceInetSockSetState, nil)
	if err != nil {
		log.Printf("Warning: Failed to attach tracepoint: %v", err)
	} else {
		defer tp.Close()
		log.Println("✓ Tracepoint attached")
	}

	// Kprobe for Egress (sendmsg)
	kpSend, err := link.Kprobe("tcp_sendmsg", objs.KprobeTcpSendmsg, nil)
	if err != nil {
		return fmt.Errorf("attaching sendmsg kprobe: %w", err)
	}
	defer kpSend.Close()
	log.Println("✓ Kprobe tcp_sendmsg attached")

	// Kprobe/Kretprobe for Ingress (recvmsg)
	kpRecv, err := link.Kprobe("tcp_recvmsg", objs.KprobeTcpRecvmsg, nil)
	if err != nil {
		return fmt.Errorf("attaching recvmsg kprobe: %w", err)
	}
	defer kpRecv.Close()

	krRecv, err := link.Kretprobe("tcp_recvmsg", objs.KretprobeTcpRecvmsg, nil)
	if err != nil {
		return fmt.Errorf("attaching recvmsg kretprobe: %w", err)
	}
	defer krRecv.Close()
	log.Println("✓ Kprobe/Kretprobe tcp_recvmsg attached")

	// 5. Open Ring Buffer
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("creating ring buffer reader: %w", err)
	}
	defer rd.Close()

	log.Println("✓ Ring buffer reader created")
	log.Println("🔍 Listening for FULL HTTP traffic... (Ctrl+C to stop)")
	log.Println()

	// 6. Processing Loop
	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	// Initialize components
	filterer := filter.NewFilterer()

	// Create output directory if not exists
	logDir := "/var/log/http-tracer"
	if err := os.MkdirAll(logDir, 0755); err != nil {
		log.Printf("Warning: Could not create log dir, falling back to local: %v", err)
		logDir = "."
	}
	writer, err := output.NewFileWriter(fmt.Sprintf("%s/traces.log", logDir))
	if err != nil {
		log.Fatalf("Failed to initialize file writer: %v", err)
	}
	defer writer.Close()

	log.Printf("Writing traces to %s/traces.log", logDir)

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			log.Printf("Error reading: %v", err)
			continue
		}

		// Parse Chunk
		chunk, err := events.ParseDataEvent(record.RawSample)
		if err != nil {
			log.Printf("Error parsing chunk: %v", err)
			continue
		}

		processChunk(chunk, watcher, filterer, writer)
	}
}

func processChunk(chunk *events.DataEvent, watcher *k8s.Watcher, filterer *filter.Filterer, writer *output.FileWriter) {
	// Try to detect HTTP
	data := string(chunk.Payload)
	isReq := false
	isResp := false

	if strings.HasPrefix(data, "GET ") || strings.HasPrefix(data, "POST ") ||
		strings.HasPrefix(data, "PUT ") || strings.HasPrefix(data, "DELETE ") ||
		strings.HasPrefix(data, "PATCH ") || strings.HasPrefix(data, "HEAD ") {
		isReq = true
	} else if strings.HasPrefix(data, "HTTP/") {
		isResp = true
	}

	if !isReq && !isResp {
		return // Skip non-HTTP chunks
	}

	buf := bytes.NewReader(chunk.Payload)
	bufferedReader := bufio.NewReader(buf)

	var entry output.TraceEntry
	entry.Timestamp = time.Now() // Approximate, ideally use chunk timestamp + boot time

	// --- IP FILTERING ---
	srcIP := chunk.SrcIPString()
	dstIP := chunk.DstIPString()
	if !filterer.ShouldTraceConnection(srcIP, dstIP) {
		return
	}

	entry.Src = watcher.GetPodURI(srcIP)
	entry.Dst = watcher.GetPodURI(dstIP)

	if isReq {
		req, err := http.ReadRequest(bufferedReader)
		if err != nil {
			// Partial or malformed
			return
		}

		// --- FILTERING ---
		// Check path and User-Agent
		if !filterer.ShouldTraceRequest(req.URL.Path, req.UserAgent()) {
			return // Filtered out
		}

		entry.Type = "REQUEST"
		entry.Method = req.Method
		entry.URL = req.URL.String()
		entry.Headers = make(map[string]string)
		for k, v := range req.Header {
			entry.Headers[k] = strings.Join(v, ", ")
		}

		// Body (simplified)
		bodyBytes, _ := io.ReadAll(req.Body)
		if len(bodyBytes) > 0 {
			entry.Body = string(bodyBytes)
		}

	} else if isResp {
		resp, err := http.ReadResponse(bufferedReader, nil)
		if err != nil {
			return
		}

		entry.Type = "RESPONSE"
		entry.Status = resp.Status
		entry.Headers = make(map[string]string)
		for k, v := range resp.Header {
			entry.Headers[k] = strings.Join(v, ", ")
		}

		bodyBytes, _ := io.ReadAll(resp.Body)
		if len(bodyBytes) > 0 {
			entry.Body = string(bodyBytes)
		}
	}

	// Write to file
	if err := writer.Write(entry); err != nil {
		log.Printf("Error writing trace: %v", err)
	}
}
