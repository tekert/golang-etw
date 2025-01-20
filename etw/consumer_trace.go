//go:build windows
// +build windows

package etw

import (
	"syscall"
)

// Information about the Trace
type Trace struct {
	// Can be a trace name or full file name path.
	TraceName  string
	TraceNameW *uint16

	// handle that OpenTrace returned if open = true, else 0
	handle syscall.Handle

	open bool          // True is the trace is open
	done chan struct{} // signal when trace is closed with CloseTrace

	// Keep ETW traceContext alive (don't nil it or they can be crashes.)
	ctx *traceContext

	// True if the trace is currently blocking in ProcessTrace
	processing bool

	// is a realtime trace session or etl file trace
	realtime bool

	// This is the logger info used to create the trace, after the trace is opened,
	// this struct is filled with more data.
	// The only fields that are updated on each bufferCallback are: Filled and BuffersRead.
	TraceLogFile *EventTraceLogfile

	// Trace Properties stats
	Properties *EventTraceProperties2

	// The RTLostEvent event type indicates that one or more realtime events were lost.
	// The RTLostEvent and RTLostBuffer event types are delivered before processing
	// events from the buffer.
	RTLostEvents uint64

	// The RTLostBuffer event type indicates that one or more realtime buffers were lost.
	RTLostBuffer uint64

	// The RTLostFile indicates that the backing file used by the AutoLogger to capture events was lost.
	RTLostFile uint64

	// The number of events that were proccesed with errors.
	ErrorEvents uint64

	// Numbers of properties that where skipped/lost due parsing errors.
	ErrorPropsParse uint64
}

func (t *Trace) Clone() *Trace {
	cpy := *t
	cpy.done = nil
	cpy.ctx = nil
	return &cpy
}

// not used
func (t *Trace) IsTraceOpen() bool {
	if t.done == nil {
		return false
	}
	select {
	case <-t.done:
		return false
	default:
		return true
	}
}

func (t *Trace) QueryTrace() *EventTraceProperties2 {
	if t.realtime {
		err := QueryTrace(t.TraceNameW, t.Properties)
		if err == nil {
			return t.Properties
		}
	}
	return nil
}

func newTrace(tname string) *Trace {
	t := &Trace{}
	t.done = make(chan struct{})

	t.Properties = NewQueryTraceProperties(tname)
	t.TraceName = tname
	t.TraceNameW, _ = syscall.UTF16PtrFromString(tname)

	if !isETLFile(tname) {
		t.realtime = true
	}

	return t
}
