/*
Package triggers

# Creates a trigger interface used by the rules engine

Author: Wayne du Preez
*/
package triggers

import (
	"context"
	"time"
)

// Trigger defines the interface that all triggers must implement.
// It emits TriggerEvents to the provided channel and respects context cancellation.
type Trigger interface {
	Start(ctx context.Context, out chan<- TriggerEvent) error
}

// TriggerEvent represents a signal emitted by a trigger.
// It contains metadata and a flexible payload for rule evaluation.
type TriggerEvent struct {
	Name      string            // Trigger name used to workout which rule it associates with
	Type      string            // Trigger type (e.g. "timer", "pcap", "metrics")
	Timestamp time.Time         // When the event occurred
	Payload   map[string]any    // Arbitrary data emitted by the trigger
	Meta      map[string]string // Optional metadata (e.g. rule ID, trigger ID)
}
