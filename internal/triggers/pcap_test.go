package triggers

import (
	"context"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestPcapTrigger_EmitsEvent(t *testing.T) {
	mockPackets := make(chan gopacket.Packet, 100)
	for i := 0; i < 50; i++ {
		mockPackets <- gopacket.NewPacket([]byte{}, layers.LayerTypeEthernet, gopacket.Default)
	}
	close(mockPackets)

	trigger := &PcapTrigger{
		iface:         "mock0",
		filter:        "tcp port 80",
		trafficAbove:  40,
		duration:      2 * time.Second,
		checkInterval: 500 * time.Millisecond,
		source:        &mockPacketSource{packets: mockPackets},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	events := make(chan TriggerEvent, 1)
	err := trigger.Start(ctx, events)
	if err != nil {
		t.Fatalf("trigger failed: %v", err)
	}

	select {
	case evt := <-events:
		if evt.Name != "pcap" {
			t.Errorf("unexpected event name: %s", evt.Name)
		}
		if count, ok := evt.Payload["packet_count"].(int); !ok || count < 40 {
			t.Errorf("unexpected packet count: %v", evt.Payload["packet_count"])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("expected event but got none")
	}
}
