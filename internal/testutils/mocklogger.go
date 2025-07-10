/*
Package testutils

This provides test utilities used for testing purposes.

Author: Wayne du Preez
*/
package testutils

import (
	"fmt"
)

// MockLogger is a mock implementation of the logger.Log interface for testing.
type MockLogger struct{}

// NewMockLogger creates a new instance of MockLogger.
func NewMockLogger() *MockLogger {
	return &MockLogger{}
}

// Debug implements the logger.Log interface for debug messages.
func (m *MockLogger) Debug(msg string, keysAndValues ...any) {
	fmt.Printf("DEBUG: %s\n", msg)
}

// Info implements the logger.Log interface for info messages.
func (m *MockLogger) Info(msg string, keysAndValues ...any) {
	fmt.Printf("INFO: %s\n", msg)
}

// Warn implements the logger.Log interface for warning messages.
func (m *MockLogger) Warn(msg string, keysAndValues ...any) {
	fmt.Printf("WARN: %s\n", msg)
}

// Error implements the logger.Log interface for error messages.
func (m *MockLogger) Error(msg string, keysAndValues ...any) {
	fmt.Printf("ERROR: %s\n", msg)
}
