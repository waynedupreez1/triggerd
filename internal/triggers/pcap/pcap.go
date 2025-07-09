/*
Package pcap

This provides the pcap trigger which does the following:
1. Captures network traffic on a specified interface
2. Applies a BPF filter
3. Counts packets over a specified duration
4. Emits a TriggerEvent if the packet count exceeds a threshold

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

// PacketSourceTrigger implements the Trigger interface.
type Trigger struct {
	stream          StreamInitializer
	log             logger.Log
	winDuration     time.Duration
	checkInterval   time.Duration
}

// Create a new PcapTrigger with the given configuration.
func NewPcapTrigger(log logger.Log, iface string, winDuration time.Duration,
					checkInterval time.Duration) (*Trigger, error) {
	
	streamInitializer := &PcapStreamInitializer {
		log: log,
		iface: iface,
	}
	return &Trigger {
		stream: 		streamInitializer,  
		winDuration:      winDuration,
		checkInterval: checkInterval,
	}, nil
}

// Start begins packet capture and emits TriggerEvents every CheckInterval.
func (p *Trigger) Start(ctx context.Context, out chan<- triggers.TriggerEvent) error {
	packetStream, err := p.stream.Open(p.stream.iface)
	if err != nil {
		e := fmt.Errorf("failed to open pcap on interface %s: %w", p.iface, err)
		p.log.Error(e.Error())
		return e
	}
	defer packetStream.Close()

	if p.filter != "" {
		if err := packetStream.SetFilter(p.filter); 
			err != nil {
				e := fmt.Errorf("failed to set filter %s on interface %s: %w", p.filter, p.iface,
								err)
				p.log.Error(e.Error())
				return e
		}
	}

	ticker := time.NewTicker(p.checkInterval)
	defer ticker.Stop()

	var packetCount int
	windowStart := time.Now()

	for {
		select {
		case <-ctx.Done():
			return nil

		case <-ticker.C:
			elapsed := time.Since(windowStart)
			if elapsed >= p.winDuration {
				out <- triggers.TriggerEvent{
					Name:      "pcap",
					Source:    p.iface,
					Timestamp: time.Now(),
					Payload: map[string]interface{}{
						"packet_count": packetCount,
						"filter":       p.filter,
						"duration":     p.winDuration.Seconds(),
					},
				}
				packetCount = 0
				windowStart = time.Now()
			}

		case _, ok := <-packetStream.Packets():
			if !ok {
				return fmt.Errorf("packet channel closed")
			}
			packetCount++
		}
	}
}
