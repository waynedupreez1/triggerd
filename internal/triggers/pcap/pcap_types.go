/*
Package pcap

This provides some interfaces to allow for injecting test implementations

Author: Wayne du Preez
*/
package pcap

import (
	"github.com/google/gopacket"
)

// Stream is an interface we use to abstract the packet source initializer.
type Stream interface {
	Open(iface string) (PacketStream, error)
}

// PacketStream is an interface that abstracts the packet source.
type PacketStream interface {
	SetFilter(filter string) error
	Packets() <-chan gopacket.Packet
	Close()
}