package triggers

import (
	"fmt"
	"time"

	"triggerd/internal/logger"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// PcapPacketStream is an implementation of PacketStream that 
// uses pcap to read packets from a live interface.
type PcapPacketStream struct {
	log 		logger.Log
    handle       *pcap.Handle
    packetSource *gopacket.PacketSource
}

// NewPacketStreamFromHandle creates a new RealPacketStream from an existing pcap handle.
func NewPacketStreamFromHandle(handle *pcap.Handle) *PcapPacketStream{
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

func (r *PcapPacketStream) SetBPFFilter(filter string) error {
	if filter == "" {
		r.log.Info("Filter not given, skipping BPF filter setup")
		return nil // No filter to set
	}
	if err := r.handle.SetBPFFilter(filter); err != nil {
		var e = fmt.Errorf("failed to set BPF filter: %s, err: %w", filter, err)
		r.log.Error(e.Error())
		return e
	}
	return nil
}

type PcapPacketStreamOpen struct{}

func (r *PcapPacketStreamOpen) OpenLive(iface string, snaplen int32, promisc bool,
	 								timeout time.Duration) (PacketStream, error) {
	handle, err := pcap.OpenLive(iface, snaplen, promisc, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to open live pcap: %w", err)
	}
	return NewPacketStreamFromHandle(handle), nil
}
