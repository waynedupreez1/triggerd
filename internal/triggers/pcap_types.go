package triggers

import (
	"time"
	"github.com/google/gopacket"
)

// GetPacketStream is an interface that hides the fact that we
// use pcap to open a live packet source.
type GetPacketStream interface {
	OpenLive(iface string, snaplen int, promisc bool, timeout time.Duration) (PacketStream, error)
}

// PacketStream is an interface that abstracts the packet source.
type PacketStream interface {
	SetBPFFilter(filter string) error
	Packets() <-chan gopacket.Packet
	Close()
}