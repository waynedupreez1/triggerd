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
	Name      string                 // Trigger type (e.g. "timer", "pcap", "metrics")
	Source    string                 // Optional: instance ID or source (e.g. "eth0", "cpu")
	Timestamp time.Time              // When the event occurred
	Payload   map[string]interface{} // Arbitrary data emitted by the trigger
	Meta      map[string]string      // Optional metadata (e.g. rule ID, trigger ID)
}

// ConfigurableTrigger is an optional interface for triggers that support dynamic configuration.
type ConfigurableTrigger interface {
	Trigger
	Configure(cfg map[string]interface{}) error
}

// Factory is a function that creates a new trigger instance from a config map.
type Factory func(cfg map[string]any) (Trigger, error)
