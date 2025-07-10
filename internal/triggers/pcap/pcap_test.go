package pcap

import (
	_ "fmt"
	"testing"
	"time"
	_ "triggerd/internal/testutils"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// MockStream implements the Stream interface
type MockStream struct {
	packetAmount   int
	packetSendWait time.Duration
}

func (m *MockStream) Open(iface string) (PacketStream, error) {
	return NewMockPacketStream(m.packetAmount, m.packetSendWait), nil
}

// MockPacketStream implements the PacketStream interface
type MockPacketStream struct {
	packetChan chan gopacket.Packet
	closed     bool
}

func NewMockPacketStream(packetAmount int, packetSendWait time.Duration) *MockPacketStream {
	m := &MockPacketStream{
		packetChan: make(chan gopacket.Packet, packetAmount),
	}
	go m.generateMockPackets(packetAmount, packetSendWait)
	return m
}

func (m *MockPacketStream) SetFilter(filter string) error {
	// No-op for mock
	return nil
}

func (m *MockPacketStream) Packets() <-chan gopacket.Packet {
	return m.packetChan
}

func (m *MockPacketStream) Close() {
	if !m.closed {
		close(m.packetChan)
		m.closed = true
	}
}

func (m *MockPacketStream) generateMockPackets(packetAmount int, packetSendWait time.Duration) {
	for range packetAmount {
		eth := &layers.Ethernet{
			SrcMAC:       []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
			DstMAC:       []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
			EthernetType: layers.EthernetTypeIPv4,
		}

		ip := &layers.IPv4{
			SrcIP:    []byte{192, 168, 1, 1},
			DstIP:    []byte{192, 168, 1, 2},
			Protocol: layers.IPProtocolTCP,
		}

		tcp := &layers.TCP{
			SrcPort: 1234,
			DstPort: 80,
		}

		// Add actual payload data
		payload := gopacket.Payload([]byte("Hello, this is mock TCP data!"))

		buffer := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{}
		gopacket.SerializeLayers(buffer, opts, eth, ip, tcp, payload)

		packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
		m.packetChan <- packet

		time.Sleep(packetSendWait)
	}

	m.Close()
}

// This test is for a real pcap stream, it will capture packets on the specified interface
// and print their metadata. Make sure to run this with appropriate permissions.
// func TestRealPcapStream(t *testing.T) {
// 	// Setup
// 	mockLogger := testutils.NewMockLogger()

// 	RealPcapStream := NewRealPcapStream(mockLogger)

// 	pcapTrigger, _ := NewPcapTrigger(mockLogger, RealPcapStream, "eth0", "", 5, 5)

// 	packetStream, err := pcapTrigger.stream.Open("eth0")
// 	if err != nil {
// 		t.Fatalf("failed to open pcap: %v", err)
// 	}
// 	defer packetStream.Close()

// 	packets := packetStream.Packets()
// 	for pkt := range packets {
// 		fmt.Print("Captured packet timestamp:", pkt.Metadata().Timestamp, "\n")
// 		fmt.Print("Captured packet data size:", pkt.Metadata().CaptureLength, "\n")
// 	}
// }

func TestMockPacketStream(t *testing.T) {

	stream := &MockStream{
		packetAmount:   10,
		packetSendWait: time.Second * 10,
	}
	ps, err := stream.Open("mock0")
	if err != nil {
		t.Fatalf("Failed to open stream: %v", err)
	}

	for pkt := range ps.Packets() {
		t.Logf("Received mock packet: % x", pkt.Data())
	}
}

// func TestPcapTrigger_EmitsEvent(t *testing.T) {
// 	mockPackets := make(chan gopacket.Packet, 100)
// 	for i := 0; i < 50; i++ {
// 		mockPackets <- gopacket.NewPacket([]byte{}, layers.LayerTypeEthernet, gopacket.Default)
// 	}
// 	close(mockPackets)

// 	trigger := &PcapTrigger{
// 		iface:         "mock0",
// 		filter:        "tcp port 80",
// 		trafficAbove:  40,
// 		duration:      2 * time.Second,
// 		checkInterval: 500 * time.Millisecond,
// 		source:        &mockPacketSource{packets: mockPackets},
// 	}

// 	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
// 	defer cancel()

// 	events := make(chan TriggerEvent, 1)
// 	err := trigger.Start(ctx, events)
// 	if err != nil {
// 		t.Fatalf("trigger failed: %v", err)
// 	}

// 	select {
// 	case evt := <-events:
// 		if evt.Name != "pcap" {
// 			t.Errorf("unexpected event name: %s", evt.Name)
// 		}
// 		if count, ok := evt.Payload["packet_count"].(int); !ok || count < 40 {
// 			t.Errorf("unexpected packet count: %v", evt.Payload["packet_count"])
// 		}
// 	case <-time.After(3 * time.Second):
// 		t.Fatal("expected event but got none")
// 	}
// }
