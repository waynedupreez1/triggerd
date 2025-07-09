/*
Package pcap

This provides some interfaces to allow for injecting test implementations

Author: Wayne du Preez
*/
package pcap

import (
	"github.com/google/gopacket"
)

// StreamInitializer is an interface we use to abstract the packet source.
type StreamInitializer interface {
	Open() (PacketStream, error)
}

// PacketStream is an interface that abstracts the packet source.
type PacketStream interface {
	SetFilter(filter string) error
	Packets() <-chan gopacket.Packet
	Close()
}