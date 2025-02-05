package etw

import (
	"sync"
	"sync/atomic"
	"time"
)

// EventBuffer just batches events before sending them to the output channel.
// The sweet spot is 20 events per batch and 200ms timeout.
// if not enough events are queued, it will flush the buffer after 200ms.

// It's better to define your own EventCallback either way.
// using batches as payloads still has 6% overhead Total compared to callback.

// When sending pointers (8 bytes) one by one trough a channel:
// In benchmarks performs 16% worse overall (a lot) for high concurrent events.
//
// While using only 1 callback/ProcessTrace thread: (1 trace only):
// channels overhead comes from runtime.chansed(2.2%), runtime.send(1.2%),
// runtime.schedule(3,14%), runtime.wakup (6,6%) (cgo stdcall1 and stdcall2),
// runtime.mallocgc (1,5%) and runtime.lock2(1,54%)
// for a total of ~16% of the time of the whole process is spent on this.
// In the end, don't use go channels for small playloads.

// Used to store events in a buffer before sending them to the output channel.
// This is used to batch events and avoid sending them one by one.
// Wich is more efficient.
type EventBuffer struct {
	sync.Mutex

	// The maximum number of events that can be stored in the batch.
	// This the ammout of events received before flushing the buffer.
	// Default: 20
	BatchSize int

	// The maximum time to wait before flushing the buffer.
	// Used when less than BatchSize events are queued.
	// Default: 200ms
	Timeout time.Duration

	// Queues
	skippableEvents    []*Event
	nonskippableEvents []*Event

	// Output channel
	skipped *atomic.Uint64
	events  chan []*Event

	timer  *time.Timer // flush timer
	closed bool
}

// Flushes and then closes the channel
func (e *EventBuffer) close() {
	e.Lock()
	defer e.Unlock()
	if e.closed {
		return
	}
	if e.timer != nil {
		e.timer.Stop()
		e.timer = nil
	}
	e.flush() // important to force flush any remaining events
	e.closed = true
	close(e.events)
}

func (e *EventBuffer) ForceFlush() {
	e.Lock()
	defer e.Unlock()
	if e.closed {
		return
	}
	e.flush()
}

// flush processes and dispatches both skippable
// and non-skippable events through the Events channel.
func (e *EventBuffer) flush() {
	// Process skippable events if any
	if len(e.skippableEvents) > 0 {
		// copy slice (it's going to be reseted after sending it)
		batch := append([]*Event(nil), e.skippableEvents...)
		select {
		case e.events <- batch:
		default:
			// Channel full, increment skip counter
			e.skipped.Add(uint64(len(batch)))
			for _, e := range batch {
				e.Release()
			}
		}
		e.skippableEvents = e.skippableEvents[:0]
	}

	// Process non-skippable events - blocks if channel is full
	if len(e.nonskippableEvents) > 0 {
		batch := append([]*Event(nil), e.nonskippableEvents...)
		e.events <- batch
		// make sure to start at 0 for the next appends
		e.nonskippableEvents = e.nonskippableEvents[:0]
	}
}

// Blocks if channel buffer is full for non skipable events.
func (e *EventBuffer) Send(event *Event) {
	e.Lock()
	defer e.Unlock()

	// return if channel is already closed.
	if e.closed {
		return
	}

	// Add event to queue
	if event.Flags.Skippable {
		e.skippableEvents = append(e.skippableEvents, event)
	} else {
		e.nonskippableEvents = append(e.nonskippableEvents, event)
	}

	// Flush if events queues reached maximum size
	if (len(e.skippableEvents) + len(e.nonskippableEvents)) >= e.BatchSize {
		// Stop timer since we are flushing
		if e.timer != nil {
			e.timer.Stop()
			e.timer = nil
		}
		e.flush() // may block if channel is full for nonskippableEvents
		return
	}

	// Start timer to flush queue if not enough events come in.
	if e.timer == nil {
		e.timer = time.AfterFunc(e.Timeout, func() {
			e.Lock()
			// if timer is still active, flush events
			if e.timer != nil && !e.closed {
				e.flush()
				e.timer = nil
			}
			e.Unlock()
		})
	}
}
