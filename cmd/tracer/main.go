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

	"github.com/charankamal20/cluster-traffic-monitor/internal/events"
	"github.com/charankamal20/cluster-traffic-monitor/internal/k8s"

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

		// --- Simple Reassembly & Parsing (Stateless for now, assumes headers in one chunk) ---
		// In a real production system, we would buffer chunks by Flow ID (PID+TID+Socket).
		// For this demo, we assume the first chunk often contains headers and print them.

		processChunk(chunk, watcher)
	}
}

func processChunk(chunk *events.DataEvent, watcher *k8s.Watcher) {
	// Try to detect HTTP
	data := string(chunk.Payload)
	isReq := false
	isResp := false

	if strings.HasPrefix(data, "GET ") || strings.HasPrefix(data, "POST ") ||
		strings.HasPrefix(data, "PUT ") || strings.HasPrefix(data, "DELETE ") {
		isReq = true
	} else if strings.HasPrefix(data, "HTTP/") {
		isResp = true
	}

	if !isReq && !isResp {
		return // Skip non-HTTP chunks (bodies without headers in this simple version)
	}

	// Enrich with K8s info
	srcPod := watcher.GetPodByIP(chunk.SrcIPString())
	dstPod := watcher.GetPodByIP(chunk.DstIPString())

	srcLabel := chunk.SrcIPString()
	if srcPod != nil {
		srcLabel = fmt.Sprintf("%s/%s (%s)", srcPod.Namespace, srcPod.Name, srcPod.IP)
	}
	dstLabel := chunk.DstIPString()
	if dstPod != nil {
		dstLabel = fmt.Sprintf("%s/%s (%s)", dstPod.Namespace, dstPod.Name, dstPod.IP)
	}

	// Parse Headers
	buf := bytes.NewReader(chunk.Payload)
	bufferedReader := bufio.NewReader(buf)

	fmt.Println("----------------------------------------------------------------")
	if isReq {
		req, err := http.ReadRequest(bufferedReader)
		if err != nil {
			fmt.Printf("Parsed PARTIAL Request from %s -> %s\n", srcLabel, dstLabel)
			fmt.Println(data) // Fallback to printing raw
		} else {
			fmt.Printf("HTTP REQUEST: %s %s\n", req.Method, req.URL)
			fmt.Printf("From: %s\nTo:   %s\n", srcLabel, dstLabel)
			fmt.Println("Headers:")
			for k, v := range req.Header {
				fmt.Printf("  %s: %s\n", k, strings.Join(v, ", "))
			}

			// Print Body
			bodyBytes, _ := io.ReadAll(req.Body)
			if len(bodyBytes) > 0 {
				fmt.Printf("\nBody (%d bytes):\n%s\n", len(bodyBytes), string(bodyBytes))
			}
		}
	} else if isResp {
		resp, err := http.ReadResponse(bufferedReader, nil)
		if err != nil {
			fmt.Printf("Parsed PARTIAL Response from %s -> %s\n", srcLabel, dstLabel)
			fmt.Println(data)
		} else {
			fmt.Printf("HTTP RESPONSE: %s\n", resp.Status)
			fmt.Printf("From: %s\nTo:   %s\n", srcLabel, dstLabel)
			fmt.Println("Headers:")
			for k, v := range resp.Header {
				fmt.Printf("  %s: %s\n", k, strings.Join(v, ", "))
			}

			// Print Body
			bodyBytes, _ := io.ReadAll(resp.Body)
			if len(bodyBytes) > 0 {
				fmt.Printf("\nBody (%d bytes):\n%s\n", len(bodyBytes), string(bodyBytes))
			}
		}
	}
	fmt.Println("----------------------------------------------------------------")
}
