/*
	Package logger

Creates a logging interface used by all other packages
pretty much uses slog for logging

Author: Wayne du Preez
*/
package logger

import (
	"log/slog"
	"os"
)

// LogLevel represents the severity of the log message.
type LogLevel int

// Debug, Info, Warn, and Error are supported log levels.
const (
	Debug LogLevel = iota
	Info
	Warn
	Error
)

// Log defines the logging interface used throughout the application.
type Log interface {
	Debug(msg string, keysAndValues ...any)
	Info(msg string, keysAndValues ...any)
	Warn(msg string, keysAndValues ...any)
	Error(msg string, keysAndValues ...any)
}

type slogLogger struct {
	logger *slog.Logger
}

// New creates a new ILogger with the specified log level.
func New(logLevel LogLevel) Log {

	level := new(slog.LevelVar)

	switch logLevel {
	case Debug:
		level.Set(slog.LevelDebug)
	case Info:
		level.Set(slog.LevelInfo)
	case Warn:
		level.Set(slog.LevelWarn)
	case Error:
		level.Set(slog.LevelError)
	}

	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})

	logger := slogLogger{
		logger: slog.New(handler),
	}

	return &logger
}

// Debug allows for logging debug messages
func (l *slogLogger) Debug(msg string, keysAndValues ...any) {

	l.logger.Debug(msg, keysAndValues...)
}

// Info allows for logging info messages
func (l *slogLogger) Info(msg string, keysAndValues ...any) {
	l.logger.Info(msg, keysAndValues...)
}

// Warn allows for logging warn messages
func (l *slogLogger) Warn(msg string, keysAndValues ...any) {
	l.logger.Warn(msg, keysAndValues...)
}

// Error allows for logging error messages
func (l *slogLogger) Error(msg string, keysAndValues ...any) {
	l.logger.Error(msg, keysAndValues...)
}
