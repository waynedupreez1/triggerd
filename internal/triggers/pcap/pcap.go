/*
Package pcap

This provides the pcap trigger which does the following:
1. Captures network traffic on a specified interface
2. Applies a BPF filter if any
3. Counts packets over specified time window
4. Counts data size over specified time window
4. Emits a TriggerEvent at specified interval

Author: Wayne du Preez
*/
package pcap

import (
	"context"
	"fmt"
	"time"

	"triggerd/internal/logger"
	"triggerd/internal/triggers"
)

// PacketSourceTriggerConfig defines the YAML-parsed config for the PCAP trigger.
type PacketSourceTriggerConfig struct {
	Interface     string        `yaml:"interface"`      // Pcap interface name, e.g. "eth0"
	Filter        string        `yaml:"filter"`         // Pcap filter expression, e.g."tcp port 80"
	WinDuration   time.Duration `yaml:"duration"`       // A rolling window duration, e.g. "5s"
	CheckInterval time.Duration `yaml:"check_interval"` // How often to check traffic, e.g. "10s"
}

// PcapTrigger implements the Trigger interface.
type PcapTrigger struct {
	stream        Stream
	log           logger.Log
	triggerName   string
	iface         string
	filter        string
	winDuration   time.Duration
	checkInterval time.Duration
}

func NewPcapTrigger(log logger.Log, stream Stream, iface string, filter string,
					winDuration time.Duration, checkInterval time.Duration, 
					triggerName string) (triggers.Trigger, error) {

	return &PcapTrigger{
		stream:        stream,
		log:           log,
		triggerName:   triggerName,
		iface:         iface,
		filter:        filter,
		winDuration:   winDuration,
		checkInterval: checkInterval,
	}, nil
}

// Start begins packet capture and emits TriggerEvents every CheckInterval.
func (p *PcapTrigger) Start(ctx context.Context, out chan<- triggers.TriggerEvent) error {
	packetStream, err := p.stream.Open(p.iface)
	if err != nil {
		e := fmt.Errorf("failed to open pcap on interface %s: %w", p.iface, err)
		p.log.Error(e.Error())
		return e
	}
	defer packetStream.Close()

	if p.filter != "" {
		if err := packetStream.SetFilter(p.filter); err != nil {
			e := fmt.Errorf("failed to set filter %s on interface %s: %w", p.filter, p.iface, err)
			p.log.Error(e.Error())
			return e
		}
	}

	ticker := time.NewTicker(p.checkInterval)
	defer ticker.Stop()

	var packetCount int
	var packetSizeBytes int
	windowStart := time.Now()

	for {
		select {
		case <-ctx.Done():
			return nil

		// Every checkInterval this case runs
		case <-ticker.C:
			elapsed := time.Since(windowStart)
			// Have the window duration expired? Send a trigger with the payload
			if elapsed >= p.winDuration {
				out <- triggers.TriggerEvent{
					Name:      p.triggerName,
					Type: "pcap",
					Timestamp: time.Now(),
					Payload: map[string]any{
						"packetSizeBytes": packetSizeBytes,
						"packetCount":     packetCount,
						"filter":          p.filter,
						"duration":        p.winDuration.Seconds(),
					},
				}
				packetCount = 0
				packetSizeBytes = 0
				windowStart = time.Now()
			}

		case pkt, ok := <-packetStream.Packets():
			if !ok {
				e := fmt.Errorf("packet channel closed")
				p.log.Info(e.Error())
				return e
			}
			packetCount++
			packetSizeBytes = +pkt.Metadata().CaptureLength
		}
	}
}
