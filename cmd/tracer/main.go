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
	connKey   events.ConnectionKey
	isRequest bool
	timestamp int64
}

var (
	dedupCache   = make(map[dedupKey]struct{})
	dedupMutex   sync.Mutex
	dedupTimeout = 5 * time.Second
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

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
	// Only process egress to avoid duplicates
	if chunk.Direction != 0 {
		slog.Info("Got ingress request")
		return
	}

	slog.Info("Got egress request")

	isReq := false
	isResp := false

	// Robustness: Strip potential leading garbage (e.g. from BPF offset issues)
	// We scan the first 128 bytes for a valid HTTP method or HTTP version.
	// This helps recover traffic even if the captured chunk starts with random kernel bytes.
	cleanData, garbageLen := stripGarbage(data)
	if garbageLen > 0 {
		slog.Warn("Stripped leading garbage from packet", "bytes", garbageLen, "garbage_hex", fmt.Sprintf("%x", data[:garbageLen]))
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
		slog.Info("Neither request nor response.")
		// Log the first 50 bytes to debug what we are actually getting
		peekLen := 50
		if len(data) < peekLen {
			peekLen = len(data)
		}
		slog.Info("Unknown data peek", "hex", fmt.Sprintf("%x", data[:peekLen]), "str", string(data[:peekLen]))
		return
	}

	buf := bytes.NewReader(data)
	bufferedReader := bufio.NewReader(buf)
	var entry output.TraceEntry
	entry.Timestamp = time.Now()

	// TCP-level IPs
	srcIP := chunk.SrcIPString()
	dstIP := chunk.DstIPString()

	if filterer.IsLoopbackTraffic(srcIP, dstIP) || !filterer.ShouldTraceIP(srcIP) || !filterer.ShouldTraceIP(dstIP) {
		slog.Info("IP blacklisted for logging: ", srcIP, dstIP)
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
		slog.Info("Should not trace connection: ", srcPodName, dstPodName, srcNs, dstNs)
		return
	}

	// ⭐ Build connection key for correlation (client → server, using POD IPs only)
	var clientIP, serverIP string
	var clientPort, serverPort uint16

	if isReq {
		// Request egress: src=client, dst=server (might be service IP, but we need pod IP)
		clientIP, clientPort = srcIP, chunk.SrcPort

		// ⭐ If dstIP is a service IP (not in pod map), we can't correlate properly
		// For now, use what we have - response will come from actual pod IP
		serverIP, serverPort = dstIP, chunk.DstPort
	} else {
		// Response egress: src=server (pod IP), dst=client
		clientIP, clientPort = dstIP, chunk.DstPort
		serverIP, serverPort = srcIP, chunk.SrcPort
	}

	// ⭐ Create consistent connection key (always client → server)
	connKey := events.ConnectionKey{
		SrcIP:   clientIP,
		SrcPort: clientPort,
		DstIP:   serverIP,
		DstPort: serverPort,
	}

	// Deduplication check
	dkey := dedupKey{
		connKey:   connKey,
		isRequest: isReq,
		timestamp: entry.Timestamp.Truncate(100 * time.Millisecond).Unix(),
	}

	dedupMutex.Lock()
	if _, exists := dedupCache[dkey]; exists {
		dedupMutex.Unlock()
		return
	}
	dedupCache[dkey] = struct{}{}
	dedupMutex.Unlock()

	// ⭐ HTTP-level src/dst (for display purposes)
	var httpSrc, httpDst string
	if isReq {
		httpSrc = watcher.GetPodURI(srcIP)
		httpDst = watcher.GetPodURI(dstIP)
	} else {
		// Response: flip for display
		httpSrc = watcher.GetPodURI(dstIP) // client
		httpDst = watcher.GetPodURI(srcIP) // server
	}

	entry.Src = httpSrc
	entry.Dst = httpDst

	if isReq {
		req, err := http.ReadRequest(bufferedReader)
		if err != nil {
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

		pendingReq := &events.PendingRequest{
			Timestamp:   entry.Timestamp,
			Method:      req.Method,
			URL:         req.URL.String(),
			Headers:     headers,
			Body:        body,
			Src:         entry.Src,
			Dst:         entry.Dst,
			IsEncrypted: false,
		}

		correlator.AddRequest(connKey, pendingReq)

		entry.Type = "REQUEST"
		entry.Method = req.Method
		entry.URL = req.URL.String()
		entry.Headers = headers
		if len(body) > 0 {
			entry.Body = body
		}

		if os.Getenv("DEBUG_BODIES") == "1" {
			slog.Info("Request captured",
				"method", req.Method,
				"url", req.URL.String(),
				"body_len", len(bodyBytes),
				"conn_key", fmt.Sprintf("%s:%d->%s:%d", connKey.SrcIP, connKey.SrcPort, connKey.DstIP, connKey.DstPort))
		}

		if err := writer.Write(entry); err != nil {
			slog.Error("Error writing request trace", "error", err)
		}

	} else if isResp {
		resp, err := http.ReadResponse(bufferedReader, nil)
		if err != nil {
			slog.Warn("Failed to parse HTTP response", "error", err)
			return
		}

		// ⭐ Nil check before using resp
		if resp == nil {
			slog.Warn("HTTP response is nil")
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

		// Try to match with pending request
		trace := correlator.MatchResponse(connKey, resp.Status, headers, respBody, entry.Timestamp)
		if trace != nil {
			if err := writer.WriteCorrelated(trace); err != nil {
				slog.Error("Error writing correlated trace", "error", err)
			}
		} else {
			// No matching request found
			if os.Getenv("DEBUG_CORRELATOR") == "1" {
				slog.Warn("No matching request found for response",
					"key", fmt.Sprintf("%s:%d->%s:%d", connKey.SrcIP, connKey.SrcPort, connKey.DstIP, connKey.DstPort),
					"status", resp.Status,
					"pending_count", len(correlator.GetPending()))
			}

			entry.Type = "RESPONSE"
			entry.Status = resp.Status
			entry.Headers = headers
			if len(respBody) > 0 {
				entry.Body = respBody
			}

			if err := writer.Write(entry); err != nil {
				slog.Error("Error writing trace", "error", err)
			}
		}
	}
}
