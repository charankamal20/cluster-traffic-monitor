package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/charankamal20/cluster-traffic-monitor/internal/events"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 bpf ../../ebpf/http_tracer.bpf.c -- -I/usr/include

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func run(ctx context.Context) error {
	// Remove resource limits for locked memory
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock: %w", err)
	}

	// Load eBPF objects
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading eBPF objects: %w", err)
	}
	defer objs.Close()

	log.Println("eBPF objects loaded successfully")

	// Attach kprobe to tcp_sendmsg
	kp, err := link.Kprobe("tcp_sendmsg", objs.KprobeTcpSendmsg, nil)
	if err != nil {
		return fmt.Errorf("attaching kprobe: %w", err)
	}
	defer kp.Close()

	log.Println("Kprobe attached to tcp_sendmsg")

	// Open ring buffer reader
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("creating ring buffer reader: %w", err)
	}
	defer rd.Close()

	log.Println("Ring buffer reader created")
	log.Println("Listening for HTTP events... (Ctrl+C to stop)")
	log.Println()

	// Read events
	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Ring buffer closed, exiting...")
				return nil
			}
			log.Printf("Error reading from ring buffer: %v", err)
			continue
		}

		// Parse event
		event, err := events.ParseEvent(record.RawSample)
		if err != nil {
			log.Printf("Error parsing event: %v", err)
			continue
		}

		// Print event
		fmt.Println(event.String())
	}
}
