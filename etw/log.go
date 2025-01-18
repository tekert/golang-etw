//go:build windows
// +build windows

package etw

import (
	"context"
	"log/slog"
	"os"
)

const (
	// Custom levels
	LogLevelTrace = slog.Level(-8)
)

// SetLoggerHandler sets a custom logger for ETW library
func SetLoggerHandler(h slog.Handler) {
	if h == nil {
		return // Keep default
	}
	slog.SetDefault(slog.New(h))
}

func SetLoggerLevel(level slog.Level) {
	slog.SetLogLoggerLevel(level)
}

func SetDebugLevel(addSource bool) {
	// Create text handler that writes to stderr
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level:     slog.LevelDebug,
		AddSource: addSource,
	})

	// Set as default logger
	slog.SetDefault(slog.New(h))
}

// Logs trace messages, level = -8
func LogTrace(msg string, args ...any) {
	slog.Default().Log(context.Background(), LogLevelTrace, msg, args...)
}

// https://pkg.go.dev/log/slog@go1.23.4#hdr-Performance_considerations
type lazyDecodeSource struct {
	ds DecodingSource
}

func (l lazyDecodeSource) LogValue() slog.Value {
	// Called only if log is enabled
	return slog.StringValue(aSource[l.ds])
}
