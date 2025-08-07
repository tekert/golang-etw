//go:build windows

package etw

import (
	"sync/atomic"
	"syscall"
)

// Information about the Trace
type Trace struct {
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

	// This is the logger info used to create the trace, after the trace is opened,
	// this struct is filled with more data.
	// traceLogFile.LogfileHeader.LostEvents measures events lost on when the trace was created,
	// for example, when consuming from a file, it will be the events lost when the file was
	// created.
	// The only fields that are updated on each bufferCallback are: Filled and BuffersRead.
	traceLogFile       EventTraceLogfile
	traceLogFileBuffer *EventTraceLogfile // Updated from bufferCallback

	// Trace EventTracePropertyData stats
	traceProps *EventTracePropertyData2

	// The RTLostEvent event type indicates that one or more realtime events were lost.
	// The RTLostEvent and RTLostBuffer event types are delivered before processing
	// events from the buffer.
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

func (t *Trace) IsTraceOpen() bool {
	return t.open
}

// GetLogFileCopy returns a copy of the internal EventTraceLogfile structure.
// This method ensures that callers receive an independent copy of the trace log file configuration,
// preventing any external modifications from affecting the original trace settings.
//
// EventTraceLogfile represents the configuration and state of an ETW (Event Tracing for Windows) log file.
// It contains critical information such as:
//   - Log file name and mode (real-time or file-based)
//   - Buffer statistics (filled amount, buffers read)
//   - Processing flags and callback functions
//   - Session-specific data like start/end times
//   - Event loss statistics from the logging session
//
// The only fields that are updated while the trace is open and processing are:
// Filled and BuffersRead fields.
// All other fields are set when the trace is opened.
func (t *Trace) GetLogFileCopy() EventTraceLogfile {
	t.updateTraceLogFile(t.traceLogFileBuffer)
	return t.traceLogFile
}

// Warning: some pointers will be invalid when the trace is closed, use [Trace.GetLogFileCopy] instead.
// This is the internal EventTraceLogfile structure that is updated by the bufferCallback.
// Use this for up to date buffer stats
func (t *Trace) GetBufferLogFile() *EventTraceLogfile {
	return t.traceLogFileBuffer
}

// updateTraceLogFile updates the traceLogFile with non-pointer fields from bufferTraceLogFile.
// (the EventTraceLogfile that is passed to the bufferCallback)
// This is useful for keeping the internal state consistent when certain fields
// are updated via callbacks.
func (t *Trace) updateTraceLogFile(bufferLogFile *EventTraceLogfile) {
	if bufferLogFile == nil {
		return
	}
	// After trace is closed some bufferLogFile pointers will be invalid memory, don't update them.

	t.traceLogFile.Filled = bufferLogFile.Filled
	//t.traceLogFile.EventsLost = bufferLogFile.EventsLost // Dont use. It's not updated.
	t.traceLogFile.BuffersRead = bufferLogFile.BuffersRead
	t.traceLogFile.BufferSize = bufferLogFile.BufferSize
	t.traceLogFile.CurrentTime = bufferLogFile.CurrentTime

	t.traceLogFile.LogfileHeader.BuffersLost = bufferLogFile.LogfileHeader.BuffersLost
	t.traceLogFile.LogfileHeader.BuffersWritten = bufferLogFile.LogfileHeader.BuffersWritten
}

// QueryTrace retrieves the status and current settings for this tracing session.
// This function uses the trace properties structure previously set during trace start.
// It resets LogFileNameOffset to 0 to maintain existing log file name settings.
//
// Returns:
//   - *EventTracePropertyData2: A pointer to the trace property data structure containing the session settings
//   - error: An error if the query operation fails, nil otherwise
func (t *Trace) QueryTrace() (prop *EventTracePropertyData2, err error) {
	err = QueryTrace(t.traceProps)
	if err != nil {
		return nil, err
	}
	return t.traceProps, err
}

func newTrace(tname string) *Trace {
	t := &Trace{}

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
