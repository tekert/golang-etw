//go:build windows

package etw

import (
	"fmt"
	"sync/atomic"
	"syscall"
)

// ConsumerTrace holds the state and statistics for a single trace session
// from the perspective of a consumer. An instance of this struct is created for
// each trace name or session that a Consumer is attached to.
type ConsumerTrace struct {
	// Can be a trace name or full file name path.
	TraceName  string
	TraceNameW *uint16

	// handle that OpenTrace returned if open = true, else 0
	handle syscall.Handle

	open bool // True is the trace is open

	// Keep ETW traceContext alive (don't nil it or they can be crashes.)
	ctx *traceContext

	// True if the trace is currently blocking in ProcessTrace
	processing bool

	// is a realtime trace session or etl file trace
	realtime bool

	// Atomically updated pointer to a cloned, safe-to-read copy of the
	// last EventTraceLogfile structure received from a buffer callback.
	//
	// NOTE: For real-time sessions, the `EventsLost` fields within this
	// structure and its `LogfileHeader` are often not populated. The number of
	// lost events is reliably reported via special "RTLostEvent" events (counted
	// in `RTLostEvents`) and by querying the session properties directly.
	// For file-based traces (ETL files), `LogfileHeader.EventsLost` reflects
	// events lost when the file was originally recorded.
	lastTraceLogfile atomic.Pointer[EventTraceLogfile]

	// Trace EventTracePropertyData stats
	traceProps *EventTracePropertyData2

	// The RTLostEvent event type indicates that one or more realtime events were lost.
	// The RTLostEvent and RTLostBuffer event types are delivered before processing
	// events from the buffer.
	//
	// This counter increments for each `RTLostEvent` notification received by the consumer.
	// Note that a single notification may represent multiple underlying events being
	// dropped by the kernel. For the authoritative total count of lost events,
	// query the session properties via `Session.QueryTrace()` or `ConsumerTrace.QueryTrace()`
	//  and check the `EventsLost` field. The two numbers are not expected to match.
	//
	//  Remarks:
	// In the Event Tracing for Windows (ETW) API, the discrepancy between the EventsLost
	// count in the EVENT_TRACE_PROPERTIES or EVENT_TRACE_PROPERTIES_V2 structures and the
	// counts of lost events received through the RT_LostEvent class can arise from several
	// factors. The EventsLost member reflects the total number of events that were not recorded
	// due to various reasons, including buffer overflows or other issues during the event
	// tracing session. In contrast, the RT_LostEvent class captures specific instances of
	// lost events, which may not account for all events that were lost during the session.
	// Therefore, the EventsLost count might include events lost before they could be categorized
	// as RT_LostEvent.
	//
	// Another reason for the higher EventsLost count could be related to the timing of when
	// events are processed and reported. The EVENT_TRACE_PROPERTIES structures are updated
	// periodically, while the RT_LostEvent class events are generated in real-time as events are lost.
	// If there are bursts of events that exceed the buffer capacity, the EventsLost count may
	// reflect those losses, while the RT_LostEvent may only capture a subset of those events
	// that were lost during specific intervals. This timing difference can lead to discrepancies
	// in the reported counts.
	//
	// Additionally, it is important to consider the context in which these counts are generated.
	// The EventsLost member provides a cumulative total of lost events throughout the entire session,
	// while the RT_LostEvent class may only report lost events that occur during the time the
	// consumer is actively processing events. If the consumer is not running or is unable to
	// process events quickly enough, it may miss reporting some lost events, leading to a lower
	// count compared to the EventsLost total.
	RTLostEvents atomic.Uint64

	// The RTLostBuffer event type indicates that one or more realtime buffers were lost.
	RTLostBuffer atomic.Uint64

	// The RTLostFile indicates that the backing file used by the AutoLogger to capture events was lost.
	RTLostFile atomic.Uint64

	// The number of events that were proccesed with errors.
	ErrorEvents atomic.Uint64

	// Numbers of properties that where skipped/lost due parsing errors.
	ErrorPropsParse atomic.Uint64
}

func (t *ConsumerTrace) IsTraceOpen() bool {
	return t.open
}

// GetLogFileCopy returns a safe-to-read copy of the last known EventTraceLogfile state.
// This structure contains statistics about the trace session, such as buffers read,
// events lost, and timing information. The returned value is a snapshot and is safe
// to use even after the trace has been closed.
//
// For real-time sessions, the `BuffersRead` field is updated on each buffer.
// However, the `EventsLost` fields are typically not updated in this structure;
// for reliable lost event counts, use `ConsumerTrace.RTLostEvents` or query the session
// properties via `Session.QueryTrace()`.
func (t *ConsumerTrace) GetLogFileCopy() *EventTraceLogfile {
	return t.lastTraceLogfile.Load()
}

// updateTraceLogFile efficiently updates only the changing non-pointer fields in place.
func (t *ConsumerTrace) updateTraceLogFile(bufferLogFile *EventTraceLogfile) {
	if bufferLogFile == nil {
		return
	}

	current := t.lastTraceLogfile.Load()
	if current == nil {
		// First time - store the pointer directly as the live copy
		t.lastTraceLogfile.Store(bufferLogFile)
		return
	}

	// Update non-pointer fields
	current.CurrentTime = bufferLogFile.CurrentTime
	current.BuffersRead = bufferLogFile.BuffersRead
	current.BufferSize = bufferLogFile.BufferSize
	current.Filled = bufferLogFile.Filled
	current.EventsLost = bufferLogFile.EventsLost

	// Copy entire LogfileHeader
	current.LogfileHeader = bufferLogFile.LogfileHeader

	// Copy Union1 fields
	current.Union1 = bufferLogFile.Union1
}

// QueryTrace retrieves the status and current settings for this tracing session.
// This is the "consumer's view" of the session. It queries the session by its
// name, allowing a consumer to get statistics for any session it is listening to,
// even if it was started by another process.
//
// The returned pointer refers to the trace's internal properties struct and should
// not be modified.
//
// Returns:
//   - *EventTracePropertyData2: A pointer to the trace property data structure containing the session settings
//   - error: An error if the query operation fails, nil otherwise
func (t *ConsumerTrace) QueryTrace() (prop *EventTracePropertyData2, err error) {
	if t.traceProps == nil {
		return nil, fmt.Errorf("trace has no session properties to query (likely a file-based trace)")
	}
	// This function uses the trace properties structure previously set during trace start.
	// It resets LogFileNameOffset to 0 to maintain existing log file name settings.
	err = QueryTrace(t.traceProps)
	if err != nil {
		return nil, err
	}
	return t.traceProps, err
}

func newConsumerTrace(tname string) *ConsumerTrace {
	t := &ConsumerTrace{}

	t.TraceName = tname
	t.TraceNameW, _ = syscall.UTF16PtrFromString(tname)

	if !isETLFile(tname) {
		t.traceProps = NewQueryTraceProperties(tname)
		t.realtime = true
	} else {
		t.realtime = false
	}

	return t
}
