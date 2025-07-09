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
	"fmt"
	"triggerd/internal/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// PcapPacketStream is an implementation of PacketStream that
// uses pcap to read packets from a live interface.
type PcapPacketStream struct {
	log          logger.Log
	handle       *pcap.Handle
	packetSource *gopacket.PacketSource
}

// NewPacketStreamFromHandle creates a new RealPacketStream from an existing pcap handle.
func NewPacketStreamFromHandle(handle *pcap.Handle) *PcapPacketStream {
	return &PcapPacketStream{
		handle:       handle,
		packetSource: gopacket.NewPacketSource(handle, handle.LinkType()),
	}
}

func (r *PcapPacketStream) Packets() <-chan gopacket.Packet {
	return r.packetSource.Packets()
}

func (r *PcapPacketStream) Close() {
	r.log.Info("Closing PcapPacketStream")
	r.handle.Close()
}

func (r *PcapPacketStream) SetFilter(filter string) error {
	if filter == "" {
		r.log.Info("Skipping BPF filter setup")
		return nil // No filter to set
	}
	if err := r.handle.SetBPFFilter(filter); err != nil {
		var e = fmt.Errorf("failed to set BPF filter: %s, err: %w", filter, err)
		r.log.Error(e.Error())
		return e
	}
	return nil
}

type PcapStreamInitializer struct {
	log logger.Log
	iface string
}

// Open just set snaplen to 1600, promisc to true, and timeout to BlockForever this 
// is the default for most packet capture scenarios.
func (r *PcapStreamInitializer) Open() (PacketStream, error) {

	interfs, err := pcap.FindAllDevs()

	if err != nil {
		e := fmt.Errorf("failed to find pcap devices: %w", err)
		r.log.Error(e.Error())
		return nil, e
	}

	// Check if the interface exists
	for _, interf := range interfs {
		if interf.Name == iface {
			err := fmt.Errorf("interface %s found", iface)
			r.log.Info(err.Error())
			break
		} else {
			err := fmt.Errorf("interface %s not found", iface)
			r.log.Warn(err.Error())
			return nil, err
		}
	}

	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		e := fmt.Errorf("failed to open live pcap on interface %s: %w", iface, err)
		r.log.Error(e.Error())
		return nil, e
	}
	return NewPacketStreamFromHandle(handle), nil
}
