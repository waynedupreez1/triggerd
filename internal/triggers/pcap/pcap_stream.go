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

type RealPcapStream struct {
	Log logger.Log
}

// Open just set snaplen to 1600, promisc to true, and timeout to BlockForever this
// is the default for most packet capture scenarios.
func (r RealPcapStream) Open(iface string) (PacketStream, error) {

	interfs, err := pcap.FindAllDevs()

	if err != nil {
		e := fmt.Errorf("failed to find pcap devices: %w", err)
		r.Log.Error(e.Error())
		return nil, e
	}

	// Check if the interface exists
	for _, interf := range interfs {
		if interf.Name == iface {
			err := fmt.Errorf("interface %s found", iface)
			r.Log.Info(err.Error())
			break
		} else {
			err := fmt.Errorf("interface %s not found", iface)
			r.Log.Warn(err.Error())
			return nil, err
		}
	}

	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		e := fmt.Errorf("failed to open live pcap on interface %s: %w", iface, err)
		r.Log.Error(e.Error())
		return nil, e
	}
	return NewRealPcapPacketStreamFromHandle(handle, r.Log), nil
}

func NewRealPcapStream(log logger.Log) RealPcapStream {
	return RealPcapStream{
		Log: log,
	}
}


// RealPcapPacketStream is an implementation of PacketStream that
// uses pcap to read packets from a live interface.
type RealPcapPacketStream struct {
	log          logger.Log
	handle       *pcap.Handle
	packetSource *gopacket.PacketSource
}

func NewRealPcapPacketStreamFromHandle(handle *pcap.Handle, log logger.Log) *RealPcapPacketStream {
	return &RealPcapPacketStream{
		log: log,
		handle:       handle,
		packetSource: gopacket.NewPacketSource(handle, handle.LinkType()),
	}
}

func (r *RealPcapPacketStream) Packets() <-chan gopacket.Packet {
	return r.packetSource.Packets()
}

func (r *RealPcapPacketStream) Close() {
	r.log.Info("Closing PcapPacketStream")
	r.handle.Close()
}

func (r *RealPcapPacketStream) SetFilter(filter string) error {
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