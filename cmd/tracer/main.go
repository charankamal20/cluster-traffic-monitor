package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/charankamal20/cluster-traffic-monitor/internal/events"
	"github.com/charankamal20/cluster-traffic-monitor/internal/filter"
	"github.com/charankamal20/cluster-traffic-monitor/internal/k8s"
	"github.com/charankamal20/cluster-traffic-monitor/internal/output"
	"github.com/charankamal20/cluster-traffic-monitor/internal/stream"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 bpf_full ../../ebpf/http_tracer_full.bpf.c -- -I/usr/include -I../../ebpf

type dedupKey struct {
	sockPtr   uint64 // ⭐ CHANGED: Use sock_ptr
	isRequest bool
	timestamp int64
}

var (
	dedupCache   = make(map[dedupKey]struct{})
	dedupMutex   sync.Mutex
	dedupTimeout = 5 * time.Second
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Dedup cache cleanup
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			dedupMutex.Lock()
			dedupCache = make(map[dedupKey]struct{})
			dedupMutex.Unlock()
		}
	}()

	if err := run(ctx); err != nil {
		slog.Error("Fatal error", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	watcher, err := k8s.NewWatcher()
	if err != nil {
		slog.Warn("Failed to create K8s watcher (running without enrichment)", "error", err)
	} else {
		if err := watcher.Start(ctx); err != nil {
			slog.Warn("Failed to start K8s watcher", "error", err)
		}
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock: %w", err)
	}

	objs := bpf_fullObjects{}
	if err := loadBpf_fullObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading eBPF objects: %w", err)
	}

	defer objs.Close()
	slog.Info("eBPF objects loaded successfully")

	tp, err := link.Tracepoint("sock", "inet_sock_set_state", objs.TraceInetSockSetState, nil)
	if err != nil {
		slog.Warn("Failed to attach tracepoint", "error", err)
	} else {
		defer tp.Close()
		slog.Info("Tracepoint attached")
	}

	kpSend, err := link.Kprobe("tcp_sendmsg", objs.KprobeTcpSendmsg, nil)
	if err != nil {
		return fmt.Errorf("attaching sendmsg kprobe: %w", err)
	}

	defer kpSend.Close()
	slog.Info("Kprobe tcp_sendmsg attached")

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
	slog.Info("Kprobe/Kretprobe tcp_recvmsg attached")

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("creating ring buffer reader: %w", err)
	}

	defer rd.Close()
	log.Println("✓ Ring buffer reader created")
	log.Println("🔍 Listening for FULL HTTP traffic... (Ctrl+C to stop)")
	log.Println()

	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	filterer := filter.NewFilterer()
	correlator := events.NewCorrelator(30 * time.Second)
	reassembler := stream.NewReassembler(30 * time.Second)

	logDir := "/var/log/http-tracer"
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		slog.Warn("Could not create log dir, falling back to local", "error", err)
		logDir = "."
	}

	writer, err := output.NewFileWriter(fmt.Sprintf("%s/traces.log", logDir))
	if err != nil {
		slog.Error("Failed to initialize file writer", "error", err)
		return fmt.Errorf("initializing file writer: %w", err)
	}

	defer writer.Close()
	slog.Info("Writing traces to file", "path", fmt.Sprintf("%s/traces.log", logDir))

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}

			slog.Error("Error reading from ring buffer", "error", err)
			continue
		}

		chunk, err := events.ParseDataEvent(record.RawSample)
		if err != nil {
			slog.Error("Error parsing chunk", "error", err)
			continue
		}

		streamKey := stream.StreamKey{
			SrcIP:   chunk.SrcIPString(),
			SrcPort: chunk.SrcPort,
			DstIP:   chunk.DstIPString(),
			DstPort: chunk.DstPort,
		}

		completeMessages := reassembler.AddChunk(streamKey, chunk.Payload, chunk.Direction)

		for _, msgData := range completeMessages {
			processCompleteMessage(msgData, chunk, watcher, filterer, writer, correlator)
		}
	}
}

func processCompleteMessage(data []byte, chunk *events.DataEvent, watcher *k8s.Watcher, filterer *filter.Filterer, writer *output.FileWriter, correlator *events.Correlator) {
	isReq := false
	isResp := false

	// Strip potential leading garbage
	cleanData, garbageLen := stripGarbage(data)
	if garbageLen > 0 {
		slog.Debug("Stripped leading garbage from packet", "bytes", garbageLen)
		data = cleanData
	}

	if bytes.HasPrefix(data, []byte("GET ")) || bytes.HasPrefix(data, []byte("POST ")) ||
		bytes.HasPrefix(data, []byte("PUT ")) || bytes.HasPrefix(data, []byte("DELETE ")) ||
		bytes.HasPrefix(data, []byte("PATCH ")) || bytes.HasPrefix(data, []byte("HEAD ")) ||
		bytes.HasPrefix(data, []byte("OPTIONS ")) {
		isReq = true
	} else if bytes.HasPrefix(data, []byte("HTTP/")) {
		isResp = true
	}

	if !isReq && !isResp {
		return
	}

	buf := bytes.NewReader(data)
	bufferedReader := bufio.NewReader(buf)

	// TCP-level IPs
	srcIP := chunk.SrcIPString()
	dstIP := chunk.DstIPString()

	if filterer.IsLoopbackTraffic(srcIP, dstIP) || !filterer.ShouldTraceIP(srcIP) || !filterer.ShouldTraceIP(dstIP) {
		return
	}

	// Resolve pods
	srcPodInfo := watcher.GetPodByIP(srcIP)
	dstPodInfo := watcher.GetPodByIP(dstIP)

	var srcPodName, dstPodName, srcNs, dstNs string
	if srcPodInfo != nil {
		srcPodName = srcPodInfo.Name
		srcNs = srcPodInfo.Namespace
	}

	if dstPodInfo != nil {
		dstPodName = dstPodInfo.Name
		dstNs = dstPodInfo.Namespace
	}

	if !filterer.ShouldTraceConnection(srcPodName, dstPodName, srcNs, dstNs) {
		return
	}

	// ⭐ Use socket pointer for correlation
	connKey := events.ConnectionKey{
		SockPtr: chunk.SockPtr,
	}

	// Deduplication check
	dkey := dedupKey{
		sockPtr:   chunk.SockPtr,
		isRequest: isReq,
		timestamp: time.Now().Truncate(100 * time.Millisecond).Unix(),
	}

	dedupMutex.Lock()
	if _, exists := dedupCache[dkey]; exists {
		dedupMutex.Unlock()
		return
	}

	dedupCache[dkey] = struct{}{}
	dedupMutex.Unlock()

	// ==================== REQUEST PROCESSING ====================
	if isReq {
		req, err := http.ReadRequest(bufferedReader)
		if err != nil {
			slog.Debug("Failed to parse HTTP request", "error", err)
			return
		}

		if filterer.IsHealthProbe(req.URL.Path, req.UserAgent(), "") {
			return
		}

		if !filterer.ShouldTraceRequest(req.URL.Path, req.UserAgent()) {
			return
		}

		bodyBytes, _ := io.ReadAll(req.Body)

		headers := make(map[string]string)
		for k, v := range req.Header {
			headers[k] = strings.Join(v, ", ")
		}

		headers = output.RedactHeaders(headers)
		contentEncoding := output.GetContentEncoding(headers)

		decompressedBody, err := output.DecompressBody(bodyBytes, contentEncoding)
		if err == nil {
			bodyBytes = decompressedBody
		}

		body := output.TruncateBody(string(bodyBytes), 8192)

		// ⭐ For REQUEST: src=client, dst=server (might be service IP)
		clientURI := watcher.GetPodURI(srcIP)
		serverURI := watcher.GetPodURI(dstIP)

		pendingReq := &events.PendingRequest{
			Timestamp:   time.Now(),
			Method:      req.Method,
			URL:         req.URL.String(),
			Headers:     headers,
			Body:        body,
			Src:         clientURI, // ⭐ Client pod who sent request
			Dst:         serverURI, // ⭐ Will be updated when response arrives
			IsEncrypted: false,
		}

		correlator.AddRequest(connKey, pendingReq)

		slog.Debug("Request captured",
			"method", req.Method,
			"url", req.URL.String(),
			"sock_ptr", chunk.SockPtr,
			"src", clientURI,
			"dst", serverURI,
			"body_len", len(bodyBytes))

		// ==================== RESPONSE PROCESSING ====================
	} else if isResp {
		resp, err := http.ReadResponse(bufferedReader, nil)
		if err != nil {
			slog.Debug("Failed to parse HTTP response", "error", err)
			return
		}

		if resp == nil {
			return
		}

		bodyBytes, _ := io.ReadAll(resp.Body)

		headers := make(map[string]string)
		for k, v := range resp.Header {
			headers[k] = strings.Join(v, ", ")
		}

		headers = output.RedactHeaders(headers)
		contentEncoding := output.GetContentEncoding(headers)

		decompressedBody, err := output.DecompressBody(bodyBytes, contentEncoding)
		if err == nil {
			bodyBytes = decompressedBody
		}

		respBody := output.TruncateBody(string(bodyBytes), 8192)

		if filterer.IsHealthProbe("", "", respBody) {
			return
		}

		// ⭐ For RESPONSE: srcIP = backend pod that sent response
		backendPodURI := watcher.GetPodURI(srcIP)

		// ⭐ Try to match with pending request using sock_ptr
		trace := correlator.MatchResponse(connKey, resp.Status, headers, respBody, time.Now(), backendPodURI)

		if trace != nil {
			// ⭐ SUCCESS! Write the correlated trace
			if err := writer.WriteCorrelated(trace); err != nil {
				slog.Error("Error writing correlated trace", "error", err)
			} else {
				slog.Info("✅ Correlated trace written",
					"method", trace.Method,
					"url", trace.URL,
					"status", trace.Status,
					"duration_ms", trace.DurationMs,
					"src", trace.Src, // ⭐ Client from request
					"dst", trace.Dst, // ⭐ Backend from response
					"sock_ptr", chunk.SockPtr)
			}
		} else {
			slog.Debug("No matching request for response",
				"sock_ptr", chunk.SockPtr,
				"status", resp.Status,
				"backend", backendPodURI)
		}
	}
}
