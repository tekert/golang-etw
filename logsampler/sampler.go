/*
Package sampler provides high-performance, concurrent-safe log sampling strategies.
It is designed for use in hot paths of applications where logging every event would
be prohibitively expensive, such as high-frequency error reporting or verbose tracing.

The package offers two main sampler implementations under a common `Sampler` interface.

--- Sampler Interface ---

The `Sampler` interface defines the core contract for all samplers:

`ShouldLog(key string, err error) bool`: The primary decision-making function.
  - `key`: A stable, unique string identifying the log call site (e.g., "database-connection-error").
  - `err`: An optional error object that can be used for more advanced sampling decisions.

`Flush()`: Triggers an immediate summary report of all currently suppressed logs.
`Close()`: Permanently shuts down the sampler, stopping any background tasks and

	performing a final flush of suppressed log summaries.

--- Implementations ---

1. DeduplicatingSampler

This is a powerful and flexible sampler that combines time-based deduplication with
optional rate-limiting. Its behavior is controlled by the `rate` parameter passed to
`NewDeduplicatingSampler(rate int, window time.Duration, ...)`.

  - Pure Time-Based Deduplication (rate <= 1):
    This is the default and most common use case for stopping log spam. It logs the
    *first* occurrence of an event for a given key, then suppresses all subsequent
    events for that key until the `window` duration has passed.
    Example: `NewDeduplicatingSampler(1, 10*time.Second, logger)` will log an error
    once, then remain silent for 10 seconds, regardless of how many more times
    the error occurs.

  - Hybrid Sampling (rate > 1):
    This mode combines the time window with 1-in-N sampling. It logs the first
    event and enters the quiet `window`. However, *within* that window, it will
    also log every Nth suppressed event, where N is the `rate`.
    Example: `NewDeduplicatingSampler(100, 10*time.Second, logger)` will log the
    first error, then for the next 10 seconds, it will also log the 100th, 200th,
    etc., suppressed errors it sees.

  - Summary Reporting:
    The `DeduplicatingSampler` automatically runs a background goroutine to
    periodically report the number of suppressed logs for each key and to clean up
    inactive keys. Calling `Flush()` or `Close()` provides an immediate, final report.

2. RateSampler

This is a simpler, lightweight sampler that only performs 1-in-N sampling. It does
not have a concept of a strict quiet period.

  - Usage: `NewRateSampler(rate int, window time.Duration)`
    It will log every `rate`-th event. The `window` is used to periodically reset
    the counter. This is useful for monitoring the ongoing frequency of very common,
    low-priority events without the overhead of the `DeduplicatingSampler`.

--- How to Use ---

 1. Create an instance of a sampler, typically once during application startup.
    The `DeduplicatingSampler` is recommended for most use cases.

    // Create a sampler that logs an error once, then suppresses for 30 seconds.
    // It uses a default logger to print summaries of suppressed logs.
    logSampler := sampler.NewDeduplicatingSampler(1, 30*time.Second, defaultLogger)

 2. In your application's hot path (e.g., a loop or a callback), use the sampler
    to decide whether to log.

    if err != nil {
    if logSampler.ShouldLog("my-error-key", err) {
    log.Error().Err(err).Msg("An error occurred")
    }
    }

 3. Ensure the sampler is flushed or closed at the appropriate lifecycle point to
    get a final summary of suppressed logs. For example, in a service's graceful
    shutdown routine:

    func (s *MyService) Stop() {
    // ... other shutdown logic ...
    logSampler.Flush() // Or logSampler.Close() if it's the final shutdown.
    }
*/
package logsampler

import (
	"sync"
	"sync/atomic"
	"time"
)

// SummaryReporter defines the interface for a logger that can report
// sampler summaries. This allows the sampler to remain decoupled from any
// specific logging library.
type SummaryReporter interface {
	LogSummary(key string, suppressedCount int64)
}

// Sampler defines the interface for deciding if a log message should be processed.
type Sampler interface {
	// ShouldLog determines if a log event should be written.
	// The key is a stable identifier for the log site.
	// The err object can be used for more advanced decisions but is optional.
	ShouldLog(key string, err error) bool
	// Flush reports a summary of any suppressed logs.
	Flush()
	// Close permanently stops the sampler and its background tasks, flushing one last time.
	Close()
}

// RateSampler provides simple, high-performance rate-based sampling.
type RateSampler struct {
	rate   int64
	window int64
	count  atomic.Int64
	last   atomic.Int64
}

// NewRateSampler creates a new rate sampler.
func NewRateSampler(rate int, window time.Duration) *RateSampler {
	s := &RateSampler{
		rate:   int64(rate),
		window: int64(window),
	}
	s.last.Store(time.Now().UnixNano())
	return s
}

// ShouldLog returns true if this event should be logged based on the rate limit.
func (s *RateSampler) ShouldLog(key string, err error) bool {
	now := time.Now().UnixNano()
	lastReset := s.last.Load()

	if now-lastReset > s.window {
		if s.last.CompareAndSwap(lastReset, now) {
			s.count.Store(0)
		}
	}
	return (s.count.Add(1)-1)%s.rate == 0
}

// Flush is a no-op for the simple RateSampler.
func (s *RateSampler) Flush() {}

// Close is a no-op for RateSampler.
func (s *RateSampler) Close() {}

// logInfo holds the sampling state for a given log key.
type logInfo struct {
	count    atomic.Int64
	lastSeen atomic.Int64
	lastLogs atomic.Int64
}

// DeduplicatingSampler provides high-performance, configurable sampling.
// Behavior is controlled by the `rate` parameter:
//   - If rate <= 1: Pure Time-Based Deduplication.
//   - If rate > 1: Hybrid Sampling (Time Window + Rate Limit).
type DeduplicatingSampler struct {
	rate     int64
	window   int64
	logs     sync.Map
	stopCh   chan struct{}
	reporter SummaryReporter // Changed from *plog.Logger
}

// NewDeduplicatingSampler creates a new sampler and starts its summary reporter.
func NewDeduplicatingSampler(rate int, window time.Duration, reporter SummaryReporter) *DeduplicatingSampler {
	s := &DeduplicatingSampler{
		rate:     int64(rate),
		window:   int64(window),
		stopCh:   make(chan struct{}),
		reporter: reporter, // Changed
	}
	// The reporter can be nil if the user doesn't want summaries.
	if s.reporter != nil {
		go s.summaryReporter()
	}
	return s
}

// ShouldLog determines if an event should be logged based on its configured strategy.
func (s *DeduplicatingSampler) ShouldLog(key string, err error) bool {
	now := time.Now().UnixNano()
	val, _ := s.logs.LoadOrStore(key, &logInfo{})
	info := val.(*logInfo)
	info.lastSeen.Store(now)

	lastLogs := info.lastLogs.Load()

	if now-lastLogs > s.window {
		if info.lastLogs.CompareAndSwap(lastLogs, now) {
			info.count.Store(0)
			return true
		}
	}

	count := info.count.Add(1)
	if s.rate > 1 && count%s.rate == 0 {
		lastLogs = info.lastLogs.Load()
		if info.lastLogs.CompareAndSwap(lastLogs, now) {
			info.count.Store(0)
			return true
		}
	}
	return false
}

// Flush triggers an immediate summary report of all currently suppressed logs.
func (s *DeduplicatingSampler) Flush() {
	s.flushSummaries()
}

func (s *DeduplicatingSampler) flushSummaries() {
	if s.reporter == nil {
		return
	}
	s.logs.Range(func(key, value any) bool {
		info := value.(*logInfo)
		if suppressedCount := info.count.Load(); suppressedCount > 0 {
			s.reporter.LogSummary(key.(string), suppressedCount)
		}
		s.logs.Delete(key)
		return true
	})
}

func (s *DeduplicatingSampler) summaryReporter() {
	tickerInterval := time.Duration(s.window * 3)
	if tickerInterval < 10*time.Second {
		tickerInterval = 10 * time.Second
	}
	ticker := time.NewTicker(tickerInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now().UnixNano()
			s.logs.Range(func(key, value any) bool {
				info := value.(*logInfo)
				lastSeen := info.lastSeen.Load()
				if now-lastSeen > int64(tickerInterval) {
					suppressedCount := info.count.Swap(0)
					if suppressedCount > 0 {
						s.reporter.LogSummary(key.(string), suppressedCount)
					}
					s.logs.Delete(key)
				}
				return true
			})
		case <-s.stopCh:
			return
		}
	}
}

// Close stops the background summary reporter and flushes any pending summaries.
func (s *DeduplicatingSampler) Close() {
	if s.reporter != nil {
		close(s.stopCh)
		s.flushSummaries()
	}
}
