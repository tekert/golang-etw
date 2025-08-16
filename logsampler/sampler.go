/*
	Package sampler provides high-performance, concurrent-safe log sampling strategies.
	It is designed for use in hot paths of applications where logging every event would
	be prohibitively expensive, such as high-frequency error reporting or verbose tracing.
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
	tickerInterval := max(time.Duration(s.window * 3), 10 * time.Second)
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
