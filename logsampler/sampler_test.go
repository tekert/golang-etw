package logsampler_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sampler "github.com/tekert/golang-etw/logsampler"
)

// testReporter is a mock implementation of the SummaryReporter interface
// used for testing. It stores summaries in a map for later inspection and is
// safe for concurrent use.
type testReporter struct {
	mu        sync.Mutex
	summaries map[string]int64
}

// newTestReporter creates a new test reporter.
func newTestReporter() *testReporter {
	return &testReporter{
		summaries: make(map[string]int64),
	}
}

// LogSummary implements the sampler.SummaryReporter interface.
func (r *testReporter) LogSummary(key string, suppressedCount int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.summaries[key] += suppressedCount
}

func TestDeduplicatingSampler(t *testing.T) {

	t.Run("FlushOnClose", func(t *testing.T) {
		reporter := newTestReporter()
		s := sampler.NewDeduplicatingSampler(1, time.Second, reporter)

		s.ShouldLog("flush-test", nil) // This one passes.
		for range 5 {
			s.ShouldLog("flush-test", nil) // These 5 are suppressed.
		}
		s.Close()

		if count, ok := reporter.summaries["flush-test"]; !ok || count != 5 {
			t.Fatalf("Expected suppressed count of 5 for 'flush-test', but got %d", count)
		}
	})

	t.Run("PureTimeBasedDeduplication", func(t *testing.T) {
		// This test doesn't check summaries, so we pass a nil reporter
		// to ensure the sampler handles it gracefully.
		s := sampler.NewDeduplicatingSampler(1, 100*time.Millisecond, nil)
		defer s.Close()

		if !s.ShouldLog("key1", nil) {
			t.Fatal("First log should pass")
		}
		if s.ShouldLog("key1", nil) {
			t.Fatal("Second log within window should be suppressed")
		}
		time.Sleep(110 * time.Millisecond)
		if !s.ShouldLog("key1", nil) {
			t.Fatal("Log after window should pass")
		}
	})

	t.Run("HybridSampling", func(t *testing.T) {
		s := sampler.NewDeduplicatingSampler(10, 100*time.Millisecond, nil)
		defer s.Close()

		if !s.ShouldLog("key1", nil) {
			t.Fatal("First log should pass")
		}
		for i := range 9 {
			if s.ShouldLog("key1", nil) {
				t.Fatalf("Log %d/10 should be suppressed", i+2)
			}
		}
		if !s.ShouldLog("key1", nil) {
			t.Fatal("11th log (10th suppressed) should pass due to rate limit")
		}
	})

	t.Run("ConcurrencyPure", func(t *testing.T) {
		s := sampler.NewDeduplicatingSampler(1, 200*time.Millisecond, nil)
		defer s.Close()
		var logCount int32
		var wg sync.WaitGroup
		for range 1000 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if s.ShouldLog("concurrent-key", nil) {
					atomic.AddInt32(&logCount, 1)
				}
			}()
		}
		wg.Wait()
		if atomic.LoadInt32(&logCount) != 1 {
			t.Errorf("Expected exactly 1 log in pure mode, but got %d", logCount)
		}
	})

	t.Run("ConcurrencyHybrid", func(t *testing.T) {
		rate := 100
		s := sampler.NewDeduplicatingSampler(rate, 200*time.Millisecond, nil)
		defer s.Close()
		var logCount int32
		var wg sync.WaitGroup
		numGoroutines := 1000
		for range numGoroutines {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if s.ShouldLog("concurrent-key", nil) {
					atomic.AddInt32(&logCount, 1)
				}
			}()
		}
		wg.Wait()
		expectedMax := 1 + int32((numGoroutines-1)/rate)
		if atomic.LoadInt32(&logCount) > expectedMax {
			t.Errorf("Expected at most %d logs in hybrid mode, but got %d", expectedMax, logCount)
		}
	})
}
