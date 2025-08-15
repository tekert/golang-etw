//go:build windows

// Package etw provides simple logging using phuslu/log library
// and a high-performance error sampler for hot paths.

package etw

import (
	"os"
	"sync/atomic"
	"time"

	plog "github.com/phuslu/log"
)

// LoggerName defines the name of a logger for configuration.
type LoggerName string

// Available logger names. Use these as keys when configuring log levels.
const (
	ConsumerLogger LoggerName = "consumer"
	SessionLogger  LoggerName = "session"
	DefaultLogger  LoggerName = "default"
)

// Sampler defines the interface for deciding if a log message should be processed.
type Sampler interface {
	// ShouldLog determines if a log event should be written.
	// The key is a stable identifier for the log site.
	// The err object can be used for more advanced decisions, like sampling
	// based on the error type or value. It can be nil.
	ShouldLog(key string, err error) bool
}

// RateSampler provides high-performance rate-based sampling for hot paths.
type RateSampler struct {
	rate   int64 // Sample 1 in N errors
	window int64 // Time window in nanoseconds
	count  int64 // Current count in window
	last   int64 // Last reset time
}

// NewRateSampler creates a new rate sampler.
func NewRateSampler(rate int, window time.Duration) *RateSampler {
	return &RateSampler{
		rate:   int64(rate),
		window: int64(window),
		count:  0,
		last:   time.Now().UnixNano(),
	}
}

// ShouldLog returns true if this error should be logged based on the rate limit.
// TODO: Add deduplication based on key and err.
func (s *RateSampler) ShouldLog(key string, err error) bool {
	now := time.Now().UnixNano()
	lastReset := atomic.LoadInt64(&s.last)

	// Reset counter if window elapsed
	if now-lastReset > s.window {
		if atomic.CompareAndSwapInt64(&s.last, lastReset, now) {
			atomic.StoreInt64(&s.count, 0)
		}
	}

	// Sample: log the 1st, (N+1)th, (2N+1)th, etc. error.
	return (atomic.AddInt64(&s.count, 1)-1)%s.rate == 0
}

// Stats returns current sampling statistics
func (s *RateSampler) Stats() (total int64, window time.Duration) {
	total = atomic.LoadInt64(&s.count)
	elapsed := time.Now().UnixNano() - atomic.LoadInt64(&s.last)
	window = time.Duration(elapsed)
	return
}

// HotpathLogger extends plog.Logger with methods for high-performance sampling.
type HotpathLogger struct {
	*plog.Logger
	sampler Sampler
}

// SampledError starts a new sampled log event with Error level.
// The key is used for deduplication. If the event is sampled out,
// a nil event is returned and the rest of the chain is ignored.
func (l *HotpathLogger) SampledError(key string) *plog.Entry {
	// For now, we pass a nil error. The sampler can be extended to use it.
	if l.sampler == nil || l.sampler.ShouldLog(key, nil) {
		return l.Logger.Error()
	}
	return nil // phuslu/log handles nil events efficiently
}

// SampledWarn starts a new sampled log event with Warn level.
func (l *HotpathLogger) SampledWarn(key string) *plog.Entry {
	if l.sampler == nil || l.sampler.ShouldLog(key, nil) {
		return l.Logger.Warn()
	}
	return nil
}

// LoggerManager manages all three loggers
type LoggerManager struct {
	writer  plog.Writer
	sampler Sampler
	loggers map[LoggerName]*plog.Logger // Use a map for scalability

	// Keep direct references for convenience and internal use
	conlog *plog.Logger
	seslog *plog.Logger
	deflog *plog.Logger
}

// Global logger manager and convenient logger variables
var (
	loggerManager *LoggerManager
	conlog        *HotpathLogger // Consumer hot path
	seslog        *plog.Logger   // Session operations
	log           *plog.Logger   // Default/everything else
)

// Initialize loggers on package import
func init() {
	loggerManager = NewLoggerManager()
	conlog = &HotpathLogger{
		Logger:  loggerManager.loggers[ConsumerLogger],
		sampler: loggerManager.sampler,
	}
	seslog = loggerManager.seslog
	log = loggerManager.deflog
}

// TODO: use async writer only on Error and above?

// NewLoggerManager creates a new logger manager with default settings
func NewLoggerManager() *LoggerManager {
	writer := &plog.IOWriter{Writer: os.Stderr}
	sampler := NewRateSampler(100, time.Second) // Sample 1 in 100 errors per second

	lm := &LoggerManager{
		writer:  writer,
		sampler: sampler,
		loggers: make(map[LoggerName]*plog.Logger),
	}

	// Create the loggers and store them in the map
	lm.loggers[ConsumerLogger] = &plog.Logger{
		Level:   plog.WarnLevel, // Higher threshold for hot path
		Writer:  writer,
		Context: plog.NewContext(nil).Str("component", string(ConsumerLogger)).Value(),
	}
	lm.loggers[SessionLogger] = &plog.Logger{
		Level:   plog.InfoLevel,
		Writer:  writer,
		Context: plog.NewContext(nil).Str("component", string(SessionLogger)).Value(),
	}
	lm.loggers[DefaultLogger] = &plog.Logger{
		Level:   plog.InfoLevel,
		Writer:  writer,
		Context: plog.NewContext(nil).Str("component", string(DefaultLogger)).Value(),
	}

	// Assign to convenient direct-access variables
	lm.conlog = lm.loggers[ConsumerLogger]
	lm.seslog = lm.loggers[SessionLogger]
	lm.deflog = lm.loggers[DefaultLogger]

	return lm
}

// SetBaseContext changes the base context for all loggers.
// This allows a consumer to add its own contextual fields.
func (lm *LoggerManager) SetBaseContext(ctx []byte) {
	for name, logger := range lm.loggers {
		logger.Context = plog.NewContext(ctx).Str("component", string(name)).Value()
	}
}

// SetWriter changes the writer for all loggers
func (lm *LoggerManager) SetWriter(writer plog.Writer) {
	lm.writer = writer
	for _, logger := range lm.loggers {
		logger.Writer = writer
	}
}

// SetLogLevels sets the log level for one or more loggers.
// Use the exported LoggerName constants (e.g., etw.ConsumerLogger) as keys.
func (lm *LoggerManager) SetLogLevels(levels map[LoggerName]plog.Level) {
	for name, level := range levels {
		if logger, ok := lm.loggers[name]; ok {
			logger.SetLevel(level)
		}
	}
}

// GetSampler returns the error sampler for hot path error logging
func (lm *LoggerManager) GetSampler() Sampler {
	return lm.sampler
}

// SetLogLevels sets the log level for one or more loggers globally.
func SetLogLevels(levels map[LoggerName]plog.Level) {
	loggerManager.SetLogLevels(levels)
}

// SetLogLevelsAll sets all registered loggers to the given level
func SetLogLevelsAll(level plog.Level) {
	levels := make(map[LoggerName]plog.Level)
	for name := range loggerManager.loggers {
		levels[name] = level
	}
	SetLogLevels(levels)
}

func SetLogDebugLevel() { SetLogLevelsAll(plog.DebugLevel) }
func SetLogInfoLevel()  { SetLogLevelsAll(plog.InfoLevel) }
func SetLogWarnLevel()  { SetLogLevelsAll(plog.WarnLevel) }
func SetLogErrorLevel() { SetLogLevelsAll(plog.ErrorLevel) }
func SetLogFatalLevel() { SetLogLevelsAll(plog.FatalLevel) }
func SetLogPanicLevel() { SetLogLevelsAll(plog.PanicLevel) }
func SetLogTraceLevel() { SetLogLevelsAll(plog.TraceLevel) }

// DisableLogging sets all loggers to OffLevel (no output)
func DisableLogging() {
	SetLogLevelsAll(99) // NoLevel
}

// SetWriter sets writer for all loggers
func SetLogWriter(writer plog.Writer) { loggerManager.SetWriter(writer) }

// SetBaseContext sets the base context for all loggers
func SetLogBaseContext(ctx []byte) { loggerManager.SetBaseContext(ctx) }

// GetLogManager returns the global logger manager
func GetLogManager() *LoggerManager { return loggerManager }
