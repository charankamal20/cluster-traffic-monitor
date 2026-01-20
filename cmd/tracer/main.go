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
	"runtime"
	"strings"
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

const (
	version = "1.0.0"

	// Configuration
	defaultLogDir            = "/var/log/http-tracer"
	defaultStreamTimeout     = 30 * time.Second
	defaultCorrelatorTimeout = 30 * time.Second
	metricsPort              = ":9090"
)

type Application struct {
	ctx           context.Context
	cancel        context.CancelFunc
	watcher       *k8s.Watcher
	filterer      *filter.Filterer
	correlator    *events.Correlator
	reassembler   *stream.Reassembler
	writer        *output.BulkWriter
	ignoredWriter *output.BulkWriter
	objs          *bpf_fullObjects
	links         []io.Closer
	ringReader    *ringbuf.Reader
	stats         *ApplicationStats
}

type ApplicationStats struct {
	StartTime        time.Time
	TotalEvents      uint64
	ProcessedEvents  uint64
	DroppedEvents    uint64
	ParseErrors      uint64
	CorrelatedTraces uint64
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: getLogLevel(),
	}))
	slog.SetDefault(logger)

	slog.Info("Starting Tracer",
		"version", version,
		"go_version", runtime.Version(),
		"num_cpu", runtime.NumCPU())

	ctx, cancel := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	defer cancel()

	app := &Application{
		ctx:    ctx,
		cancel: cancel,
		stats:  &ApplicationStats{StartTime: time.Now()},
	}

	// Start metrics server
	go app.startMetricsServer()

	if err := app.run(); err != nil {
		slog.Error("Fatal error", "error", err)
		os.Exit(1)
	}

	slog.Info("Shutdown complete")
}

func (app *Application) run() error {
	var err error
	app.watcher, err = k8s.NewWatcher()
	if err != nil {
		slog.Warn("Failed to create K8s watcher (running without enrichment)", "error", err)
	} else {
		if err := app.watcher.Start(app.ctx); err != nil {
			slog.Warn("Failed to start K8s watcher", "error", err)
		} else {
			slog.Info("Kubernetes watcher started successfully")
		}
	}

	// Remove memory lock limit
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock: %w", err)
	}

	// Load eBPF objects
	app.objs = &bpf_fullObjects{}
	if err := loadBpf_fullObjects(app.objs, nil); err != nil {
		return fmt.Errorf("loading eBPF objects: %w", err)
	}
	defer app.objs.Close()
	slog.Info("eBPF objects loaded successfully")

	// Attach tracepoint for connection tracking
	if err := app.attachTracepoint(); err != nil {
		return fmt.Errorf("attaching tracepoint: %w", err)
	}

	// Attach kprobe for data capture (egress only for production)
	if err := app.attachKprobes(); err != nil {
		return fmt.Errorf("attaching kprobes: %w", err)
	}

	// Initialize ring buffer reader
	app.ringReader, err = ringbuf.NewReader(app.objs.Events)
	if err != nil {
		return fmt.Errorf("creating ring buffer reader: %w", err)
	}
	defer app.ringReader.Close()

	slog.Info("Ring buffer reader created")

	// Initialize processing components
	app.filterer = filter.NewFilterer()
	app.correlator = events.NewCorrelator(defaultCorrelatorTimeout)
	app.reassembler = stream.NewReassembler(defaultStreamTimeout)

	// Initialize output writer
	logDir := getLogDir()
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		slog.Warn("Could not create log dir, falling back to local", "error", err)
		logDir = "."
	}

	fw, err := output.NewFileWriter(fmt.Sprintf("%s/traces.log", logDir))
	if err != nil {
		return fmt.Errorf("initializing file writer: %w", err)
	}
	// Initialize BulkWriter with 100 items buffer and 5s flush interval
	app.writer = output.NewBulkWriter(fw, 100, 5*time.Second)
	defer app.writer.Close()

	ifw, err := output.NewFileWriter(fmt.Sprintf("%s/ignored.log", logDir))
	if err != nil {
		return fmt.Errorf("initializing ignored file writer: %w", err)
	}
	app.ignoredWriter = output.NewBulkWriter(ifw, 100, 5*time.Second)
	defer app.ignoredWriter.Close()

	slog.Info("Output writers initialized", "traces", fmt.Sprintf("%s/traces.log", logDir), "ignored", fmt.Sprintf("%s/ignored.log", logDir))

	// Start processing loop
	return app.processEvents()
}

func (app *Application) attachTracepoint() error {
	tp, err := link.Tracepoint("sock", "inet_sock_set_state", app.objs.TraceInetSockSetState, nil)
	if err != nil {
		slog.Warn("Failed to attach tracepoint (connection tracking disabled)", "error", err)
		return nil // Non-fatal
	}
	app.links = append(app.links, tp)
	slog.Info("Tracepoint attached successfully")
	return nil
}

func (app *Application) attachKprobes() error {
	kpSend, err := link.Kprobe("tcp_sendmsg", app.objs.KprobeTcpSendmsg, nil)
	if err != nil {
		return fmt.Errorf("attaching tcp_sendmsg kprobe: %w", err)
	}
	app.links = append(app.links, kpSend)
	slog.Info("Kprobe tcp_sendmsg attached (egress-only mode for production)")
	return nil
}

func (app *Application) processEvents() error {
	log.Println("🔍 Listening for HTTP/HTTP2/gRPC traffic... (Ctrl+C to stop)")
	log.Println()

	// Graceful shutdown handler
	go func() {
		<-app.ctx.Done()
		slog.Info("Shutdown signal received, draining events...")
		time.Sleep(2 * time.Second) // Allow pending events to process
		app.ringReader.Close()
	}()

	// Statistics reporting
	go app.reportStats()

	for {
		record, err := app.ringReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				slog.Info("Ring buffer closed, exiting")
				return nil
			}
			slog.Error("Error reading from ring buffer", "error", err)
			app.stats.DroppedEvents++
			continue
		}

		app.stats.TotalEvents++

		// Parse event
		chunk, err := events.ParseDataEvent(record.RawSample)
		if err != nil {
			slog.Error("Error parsing chunk", "error", err)
			app.stats.ParseErrors++
			continue
		}

		// Log protocol detection
		if chunk.Protocol != events.ProtoHTTP1 {
			slog.Debug("Non-HTTP/1.x traffic detected",
				"protocol", chunk.ProtocolString(),
				"src", chunk.SrcIPString(),
				"dst", chunk.DstIPString(),
				"size", chunk.DataLen)
		}

		// Reassemble stream
		streamKey := stream.StreamKey{
			SrcIP:   chunk.SrcIPString(),
			SrcPort: chunk.SrcPort,
			DstIP:   chunk.DstIPString(),
			DstPort: chunk.DstPort,
		}

		completeMessages := app.reassembler.AddChunk(streamKey, chunk.Payload, chunk.Direction, chunk.Protocol)

		// Process complete messages
		for _, msg := range completeMessages {
			if err := app.processCompleteMessage(msg, chunk); err != nil {
				slog.Debug("Error processing message", "error", err)
			} else {
				app.stats.ProcessedEvents++
			}
		}
	}
}

func (app *Application) processCompleteMessage(msg stream.Message, chunk *events.DataEvent) error {
	// Process based on protocol
	switch msg.Protocol {
	case events.ProtoHTTP1:
		return app.processHTTP1Message(msg.Data, chunk)
	case events.ProtoHTTP2:
		return app.processHTTP2Message(msg, chunk)
	case events.ProtoGRPC:
		return app.processGRPCMessage(msg, chunk)
	default:
		return fmt.Errorf("unknown protocol: %d", msg.Protocol)
	}
}

// Update main.go - Replace skeleton with full implementation
func (app *Application) processHTTP1Message(data []byte, chunk *events.DataEvent) error {
	isReq := false
	isResp := false

	// Detect message type
	if bytes.HasPrefix(data, []byte("GET ")) || bytes.HasPrefix(data, []byte("POST ")) ||
		bytes.HasPrefix(data, []byte("PUT ")) || bytes.HasPrefix(data, []byte("DELETE ")) ||
		bytes.HasPrefix(data, []byte("PATCH ")) || bytes.HasPrefix(data, []byte("HEAD ")) ||
		bytes.HasPrefix(data, []byte("OPTIONS ")) {
		isReq = true
	} else if bytes.HasPrefix(data, []byte("HTTP/")) {
		isResp = true
	}

	if !isReq && !isResp {
		return fmt.Errorf("not HTTP/1.x message")
	}

	buf := bytes.NewReader(data)
	bufferedReader := bufio.NewReader(buf)

	// TCP-level IPs
	srcIP := chunk.SrcIPString()
	dstIP := chunk.DstIPString()

	if app.filterer.IsLoopbackTraffic(srcIP, dstIP) {
		return nil
	}

	if !app.filterer.ShouldTraceIP(srcIP) || !app.filterer.ShouldTraceIP(dstIP) {
		return nil
	}

	// Resolve pods
	srcPodInfo := app.watcher.GetPodByIP(srcIP)
	dstPodInfo := app.watcher.GetPodByIP(dstIP)

	var srcPodName, dstPodName, srcNs, dstNs string
	if srcPodInfo != nil {
		srcPodName = srcPodInfo.Name
		srcNs = srcPodInfo.Namespace
	}
	if dstPodInfo != nil {
		dstPodName = dstPodInfo.Name
		dstNs = dstPodInfo.Namespace
	}

	if !app.filterer.ShouldTraceConnection(srcPodName, dstPodName, srcNs, dstNs) {
		return nil
	}

	// Use socket pointer for correlation
	connKey := events.ConnectionKey{
		SockPtr: chunk.SockPtr,
	}

	// ==================== REQUEST PROCESSING ====================
	if isReq {
		req, err := http.ReadRequest(bufferedReader)
		if err != nil {
			slog.Debug("Failed to parse HTTP request", "error", err, "src", srcIP, "dst", dstIP)
			return err
		}

		if app.filterer.IsHealthProbe(req.URL.Path, req.UserAgent(), "") {
			return nil
		}

		if !app.filterer.ShouldTraceRequest(req.URL.Path, req.UserAgent()) {
			return nil
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
		clientURI := app.watcher.GetPodURI(srcIP)
		serverURI := app.watcher.GetPodURI(dstIP)

		pendingReq := &events.PendingRequest{
			Timestamp:   time.Now(),
			Method:      req.Method,
			URL:         req.URL.String(),
			Headers:     headers,
			Body:        body,
			Src:         clientURI,
			Dst:         serverURI,
			IsEncrypted: false,
		}

		app.correlator.AddRequest(connKey, pendingReq)
		slog.Debug("Request captured",
			"method", req.Method,
			"url", req.URL.String(),
			"sock_ptr", chunk.SockPtr,
			"src", clientURI,
			"dst", serverURI)

		// ==================== RESPONSE PROCESSING ====================
	} else if isResp {
		resp, err := http.ReadResponse(bufferedReader, nil)
		if err != nil {
			slog.Debug("Failed to parse HTTP response", "error", err)
			return err
		}

		if resp == nil {
			return fmt.Errorf("nil response")
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

		if app.filterer.IsHealthProbe("", "", respBody) {
			return nil
		}

		backendPodURI := app.watcher.GetPodURI(srcIP)

		trace := app.correlator.MatchResponse(connKey, resp.Status, headers, respBody, time.Now(), backendPodURI)
		if trace != nil {
			// Write to BulkWriter
			app.writer.WriteCorrelated(trace)

			app.stats.CorrelatedTraces++
			slog.Info("✅ Correlated trace written",
				"method", trace.Method,
				"url", trace.URL,
				"status", trace.Status,
				"duration_ms", trace.DurationMs,
				"src", trace.Src,
				"dst", trace.Dst)
		} else {
			app.ignoredWriter.WriteIgnored(output.IgnoredTraceEntry{
				Timestamp:       time.Now(),
				Status:          resp.Status,
				SockPtr:         chunk.SockPtr,
				Src:             chunk.DstIPString(),
				Dst:             chunk.SrcIPString(),
				ResponseHeaders: headers,
				ResponseBody:    respBody,
			})
		}
	}

	return nil
}

func (app *Application) processHTTP2Message(msg stream.Message, chunk *events.DataEvent) error {
	slog.Info("HTTP/2 message processed",
		"stream_id", msg.Metadata.StreamID,
		"is_request", msg.Metadata.IsRequest,
		"method", msg.Metadata.Method,
		"size", len(msg.Data))

	// Convert to standard format and process
	return app.processHTTP1Message(msg.Data, chunk)
}

func (app *Application) processGRPCMessage(msg stream.Message, chunk *events.DataEvent) error {
	slog.Info("gRPC message processed",
		"stream_id", msg.Metadata.StreamID,
		"service", msg.Metadata.Service,
		"method", msg.Metadata.Method,
		"is_request", msg.Metadata.IsRequest,
		"size", len(msg.Data))

	// Log gRPC-specific information
	// For now, also process as HTTP/2
	return app.processHTTP1Message(msg.Data, chunk)
}

func (app *Application) reportStats() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-app.ctx.Done():
			return
		case <-ticker.C:
			uptime := time.Since(app.stats.StartTime)
			reassemblerStats := app.reassembler.GetStats()

			slog.Info("Application statistics",
				"uptime", uptime.String(),
				"total_events", app.stats.TotalEvents,
				"processed_events", app.stats.ProcessedEvents,
				"dropped_events", app.stats.DroppedEvents,
				"parse_errors", app.stats.ParseErrors,
				"active_streams", reassemblerStats.ActiveStreams,
				"completed_messages", reassemblerStats.CompletedMessages,
				"events_per_sec", float64(app.stats.TotalEvents)/uptime.Seconds())
		}
	}
}

func (app *Application) startMetricsServer() {
	http.HandleFunc("/metrics", app.metricsHandler)
	http.HandleFunc("/health", app.healthHandler)
	http.HandleFunc("/stats", app.statsHandler)

	server := &http.Server{
		Addr:         metricsPort,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	slog.Info("Metrics server starting", "port", metricsPort)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("Metrics server error", "error", err)
	}
}

func (app *Application) metricsHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "# HELP http_tracer_events_total Total number of events received\n")
	fmt.Fprintf(w, "# TYPE http_tracer_events_total counter\n")
	fmt.Fprintf(w, "http_tracer_events_total %d\n", app.stats.TotalEvents)

	fmt.Fprintf(w, "# HELP http_tracer_processed_events_total Total number of events processed\n")
	fmt.Fprintf(w, "# TYPE http_tracer_processed_events_total counter\n")
	fmt.Fprintf(w, "http_tracer_processed_events_total %d\n", app.stats.ProcessedEvents)

	reassemblerStats := app.reassembler.GetStats()
	fmt.Fprintf(w, "# HELP http_tracer_active_streams Current number of active streams\n")
	fmt.Fprintf(w, "# TYPE http_tracer_active_streams gauge\n")
	fmt.Fprintf(w, "http_tracer_active_streams %d\n", reassemblerStats.ActiveStreams)
}

func (app *Application) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "OK\n")
}

func (app *Application) statsHandler(w http.ResponseWriter, r *http.Request) {
	uptime := time.Since(app.stats.StartTime)
	reassemblerStats := app.reassembler.GetStats()

	fmt.Fprintf(w, "Uptime: %s\n", uptime)
	fmt.Fprintf(w, "Total Events: %d\n", app.stats.TotalEvents)
	fmt.Fprintf(w, "Processed Events: %d\n", app.stats.ProcessedEvents)
	fmt.Fprintf(w, "Dropped Events: %d\n", app.stats.DroppedEvents)
	fmt.Fprintf(w, "Parse Errors: %d\n", app.stats.ParseErrors)
	fmt.Fprintf(w, "Active Streams: %d\n", reassemblerStats.ActiveStreams)
	fmt.Fprintf(w, "Events/sec: %.2f\n", float64(app.stats.TotalEvents)/uptime.Seconds())
}

func getLogLevel() slog.Level {
	level := os.Getenv("LOG_LEVEL")
	switch level {
	case "DEBUG":
		return slog.LevelDebug
	case "INFO":
		return slog.LevelInfo
	case "WARN":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func getLogDir() string {
	if dir := os.Getenv("LOG_DIR"); dir != "" {
		return dir
	}
	return defaultLogDir
}
