/*
Package triggers

This provides the pcap trigger whic does the following:
1. Captures network traffic on a specified interface
2. Applies a BPF filter
3. Counts packets over a specified duration
4. Emits a TriggerEvent if the packet count exceeds a threshold

Author: Wayne du Preez
*/

package triggers

import (
	"context"
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// PcapTriggerConfig defines the YAML-parsed config for the PCAP trigger.
type PcapTriggerConfig struct {
	Interface     string        `yaml:"interface"`      // Pcap interface name, e.g. "eth0"
	Filter        string        `yaml:"filter"`         // Pcap filter expression, e.g."tcp port 80"
	Duration      time.Duration `yaml:"duration"`       // A rolling window duration, e.g. "5s"
	CheckInterval time.Duration `yaml:"check_interval"` // How often to check traffic, e.g. "10s"
}

// PcapTrigger implements the Trigger interface.
type PcapTrigger struct {
	iface         string
	filter        string
	trafficAbove  int
	duration      time.Duration
	checkInterval time.Duration
}

// // NewPcapTrigger creates a new PcapTrigger from config.
// func NewPcapTrigger(cfg map[string]any) (Trigger, error) {
// 	var conf PcapTriggerConfig
// 	if err := decodeConfig(cfg, &conf); err != nil {
// 		return nil, err
// 	}

// 	return &PcapTrigger{
// 		iface:         conf.Interface,
// 		filter:        conf.Filter,
// 		trafficAbove:  conf.TrafficAbove,
// 		duration:      conf.Duration,
// 		checkInterval: conf.CheckInterval,
// 	}, nil
// }

// Start begins packet capture and emits TriggerEvents when thresholds are exceeded.
func (t *PcapTrigger) Start(ctx context.Context, out chan<- TriggerEvent) error {
	handle, err := pcap.OpenLive(t.iface, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("pcap open failed: %w", err)
	}
	defer handle.Close()

	if t.filter != "" {
		if err := handle.SetBPFFilter(t.filter); err != nil {
			return fmt.Errorf("failed to set BPF filter: %w", err)
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()

	ticker := time.NewTicker(t.checkInterval)
	defer ticker.Stop()

	var packetCount int
	windowStart := time.Now()

	for {
		select {
		case <-ctx.Done():
			return nil

		case <-ticker.C:
			elapsed := time.Since(windowStart)
			if elapsed >= t.duration {
				if packetCount >= t.trafficAbove {
					out <- TriggerEvent{
						Name:      "pcap",
						Source:    t.iface,
						Timestamp: time.Now(),
						Payload: map[string]interface{}{
							"packet_count": packetCount,
							"filter":       t.filter,
							"duration":     t.duration.Seconds(),
						},
					}
				}
				packetCount = 0
				windowStart = time.Now()
			}

		case _, ok := <-packetChan:
			if !ok {
				return fmt.Errorf("packet channel closed")
			}
			packetCount++
		}
	}
}
