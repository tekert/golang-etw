//go:build windows
// +build windows

package etw

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

var (
	//rtLostEventGuid = MustParseGUIDFromString("{6A399AE0-4BC6-4DE9-870B-3657F8947E7E}") // don't use, not evaluated compile time.

	// https://learn.microsoft.com/en-us/windows/win32/etw/rt-lostevent
	rtLostEventGuid = &GUID{ /* {6A399AE0-4BC6-4DE9-870B-3657F8947E7E}*/
		Data1: 0x6a399ae0,
		Data2: 0x4bc6,
		Data3: 0x4de9,
		Data4: [8]byte{0x87, 0x0b, 0x36, 0x57, 0xf8, 0x94, 0x7e, 0x7e},
	}

	// EventTraceGuid is used to identify a event tracing session
	EventTraceGuid = &GUID{ /* 68fdd900-4a3e-11d1-84f4-0000f80464e3 */
		Data1: 0x68fdd900,
		Data2: 0x4a3e,
		Data3: 0x11d1,
		Data4: [8]byte{0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3},
	}
)

var (
	aSource = []string{"XML instrumentation manifest", "WMI MOF class", "WPP TMF file"}
)

// SessionSlice converts a slice of structures implementing Session
// to a slice of Session.
func SessionSlice(i interface{}) (out []Session) {
	v := reflect.ValueOf(i)

	switch v.Kind() {
	case reflect.Slice:
		out = make([]Session, 0, v.Len())
		for i := 0; i < v.Len(); i++ {
			if s, ok := v.Index(i).Interface().(Session); ok {
				out = append(out, s)
				continue
			}
			panic("slice item must implement Session interface")
		}
	default:
		panic("interface parameter must be []Session")
	}

	return
}

// Once Consumer is closed discard it and create a new one.
type Consumer struct {
	sync.WaitGroup
	ctx       context.Context
	cancel    context.CancelFunc
	closed    bool

	tmu        sync.RWMutex      	// Protect trace updates
	traces2    map[string]*Trace 	//! DELETE
	traces 	  sync.Map 				// Traces Information

	lastError error

	// [1] First callback executed, it allows to filter out events
	// based on fields of raw ETW EventRecord structure. When this callback
	// returns true event processing will continue, otherwise it is aborted.
	// Filtering out events here has the lowest overhead.
	EventRecordCallback func(*EventRecord) bool

	// [2] Callback which executes after TraceEventInfo is parsed.
	// To filter out some events call Skip method of EventRecordHelper
	// As Properties are not parsed yet, trying to get/set Properties is
	// not possible and might cause unexpected behaviours.
	EventRecordHelperCallback func(*EventRecordHelper) error

	// [3] Callback executed after event properties got prepared (step before parsing).
	// Properties are not parsed yet and this is the right place to filter
	// events based only on some properties.
	// NB: events skipped in EventRecordCallback never reach this function
	EventPreparedCallback func(*EventRecordHelper) error

	// [4] Callback executed after the event got parsed and defines what to do
	// with the event (printed, sent to a channel ...)
	EventCallback func(*Event) error

	Filter EventFilter

	// The used default callback [DefaultEventCallback] outputs parsed events to this channel.
	// This channel can be used to consume events in a non-blocking way.
	Events chan *Event

	// The total number of event's lost.
	LostEvents atomic.Uint64

	// The total number of events that were skipped.
	Skipped atomic.Uint64

	// to force stop the Consumer ProcessTrace if buffer takes too long to empty.
	// stores timeout in nanoseconds
	closeTimeout time.Duration // stores timeout in nanoseconds

	// TODO(tekert) For Testing, delete later
	useOld bool
}

const contextID uint32 = 0xE7CE7CE7 // ETW magic number
type traceContext struct {
	trace    *Trace
	consumer *Consumer
	ctxID    uint32 // Magic number for validation
}

// Helper function to get the traceContext from the UserContext
func (er *EventRecord) getUserContext() *traceContext {
	return (*traceContext)(unsafe.Pointer(er.UserContext))
}
func (e *EventTraceLogfile) getContext() *traceContext {
	ctx := (*traceContext)(unsafe.Pointer(e.Context))
	if ctx.ctxID != contextID {
		return nil // Invalid/corrupted context
	}
	return ctx
}

// Uses the old version using tdhGetProperty (inneficient)
func NewConsumer_old(ctx context.Context) (c *Consumer) {
	c = NewConsumer(ctx)

	c.useOld = true

	return c
}

// NewConsumer creates a new Consumer to consume ETW
func NewConsumer(ctx context.Context) (c *Consumer) {
	c = &Consumer{
		Filter: NewProviderFilter(),
		Events: make(chan *Event, 4096),
		traces2: make(map[string]*Trace), // ! DELETE
	}

	c.ctx, c.cancel = context.WithCancel(ctx)
	c.EventRecordHelperCallback = c.DefaultEventRecordHelperCallback
	c.EventCallback = c.DefaultEventCallback

	return c
}

// Returns a deep copy of the struct, so it can be safely used after trace is closed.
// The original it's no longer valid when the Consumer is stopped. (Trace handle closed)
// When the trace is closed, this struct is cloned so it can be returned to the user.
func (c *Consumer) cloneTraceLogfile(tname string) *EventTraceLogfile {
	c.tmu.RLock()
	defer c.tmu.RUnlock()

	if t, exists := c.traces2[tname]; exists {
		if t.TraceLogFile != nil {
			return t.TraceLogFile.Clone()
		}
	}
	return nil
}

// Trace returns a copy of the trace info for a given trace name
func (c *Consumer) GetTraceCopy_old_delete(tname string) (t Trace, exists bool) {
	c.tmu.RLock()
	defer c.tmu.RUnlock()

	if t, exists := c.traces2[tname]; exists {
		return *t.Clone(), exists
	}
	return t, false
}

// Returns a copy of the current traces info
func (c *Consumer) GetTraceCopy(tname string) (t Trace, exists bool) {
    if value, ok := c.traces.Load(tname); ok {
        trace := value.(*Trace)
        return *trace.Clone(), true
    }
    return t, false
}

// gets or creates a new one if it doesn't exist
func (c *Consumer) getOrAddTrace_old_delete(name string) *Trace {
	c.tmu.Lock()
	defer c.tmu.Unlock()

	if t, exists := c.traces2[name]; exists {
		return t
	}
	t := newTrace(name)
	c.traces2[name] = t
	return t
}

// gets or creates a new one if it doesn't exist
func (c *Consumer) getOrAddTrace(name string) *Trace {
    actual, _ := c.traces.LoadOrStore(name, newTrace(name))
    return actual.(*Trace)
}

// Returns a copy of the current traces info
func (c *Consumer) GetTracesCopy_old_delete() map[string]Trace {
	c.tmu.RLock()
	defer c.tmu.RUnlock()

	// return a copy of the traces
	traces := make(map[string]Trace, len(c.traces2))
	for k, v := range c.traces2 {
		traces[k] = *v.Clone()
	}
	return traces
}

// Returns a copy of the current traces info
func (c *Consumer) GetTracesCopy() map[string]Trace {
    traces := make(map[string]Trace)
	// return a copy of the traces
    c.traces.Range(func(key, value interface{}) bool {
        traces[key.(string)] = *value.(*Trace).Clone()
        return true
    })
    return traces
}

// https://learn.microsoft.com/en-us/windows/win32/etw/rt-lostevent
// EventType{32, 33, 34}, EventTypeName{"RTLostEvent", "RTLostBuffer", "RTLostFile"}]
func (c *Consumer) handleLostEvent(e *EventRecord) {
	var traceInfo *TraceEventInfo
	var err error
	if traceInfo, _, err = e.GetEventInformation(); err == nil {
		u := e.getUserContext()
		switch traceInfo.EventDescriptor.Opcode {
		case 32:
			// The RTLostEvent event type indicates that one or more events were lost.
			u.trace.RTLostEvents++
			slog.Debug("RTLostEvent", "trace", u.trace.TraceName, "count", u.trace.RTLostEvents)
		case 33:
			// The RTLostBuffer event type indicates that one or more buffers were lost
			u.trace.RTLostBuffer++
			slog.Debug("RTLostBuffer", "trace", u.trace.TraceName, "count", u.trace.RTLostBuffer)
		case 34:
			// The RTLostFile indicates that the backing file used by the AutoLogger
			// to capture events was lost.
			u.trace.RTLostFile++
			slog.Debug("RTLostFile", "trace", u.trace.TraceName, "count", u.trace.RTLostFile)
		default:
			slog.Debug("Invalid opcode for lost event",
				"opcode", traceInfo.EventDescriptor.Opcode)
		}
	}
	c.LostEvents.Add(1)
}

// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nc-evntrace-pevent_trace_buffer_callbacka
//
// ETW event consumers implement this function to receive statistics about each buffer
// of events that ETW delivers during a trace processing Session.
// ETW calls this function after the events for each Trace Session buffer are delivered.
// The pointer received is the same on each subsequent call for the same buffer.
func (c *Consumer) bufferCallback(e *EventTraceLogfile) uintptr {
	// ensure ctx is not garbage collected after CloseTrace or it crashes invalid mem.
	ctx := e.getContext()
	if ctx != nil {
		ctx.trace.TraceLogFile = e
	}

	if c.ctx.Err() != nil {
		// if the consumer has been stopped we
		// don't process event records anymore
		// return 0 to stop ProcessTrace
		slog.Debug("bufferCallback: Context canceled, stopping ProcessTrace...")

		return 0
	}
	// we keep processing event records
	return 1
}

// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nc-evntrace-pevent_record_callback
//
// Called when ProcessTrace gets an event record.
// This is always called from the same thread as ProcessTrace,
// so it may block other events in the same trace session buffer until it returns.
// Only one event record is received at a time by each ProcessTrace thread.
// This callback can be executed concurrently only if there are multiple
// ProcessTrace goroutines with this callback set.
func (c *Consumer) callback(er *EventRecord) (re uintptr) {

	// Count the number of events with errors, but only once per event.
	errorOccurred := false
	setError := func(err error) {
		if !errorOccurred {
			errorOccurred = true
			er.getUserContext().trace.ErrorEvents++
		}
		c.lastError = err
		slog.Debug("callback error", "error", err)
	}

	// Skips the event if it is the event trace header. Log files contain this event
	// but real-time sessions do not. The event contains the same information as
	// the EVENT_TRACE_LOGFILE.LogfileHeader member that you can access when you open
	// the trace.
	if er.EventHeader.ProviderId.Equals(EventTraceGuid) &&
		er.EventHeader.EventDescriptor.Opcode == EVENT_TRACE_TYPE_INFO {
		slog.Debug("Skipping EventTraceGuid event", "event", er)
		// Skip this event.
		return
	}

	if er.EventHeader.ProviderId.Equals(rtLostEventGuid) {
		c.handleLostEvent(er)
	}

	// calling EventHeaderCallback if possible
	if c.EventRecordCallback != nil {
		if !c.EventRecordCallback(er) {
			return
		}
	}

	// we get the TraceContext from EventRecord.UserContext
	// Parse TRACE_EVENT_INFO from the event record
	if h, err := newEventRecordHelper(er); err == nil {
		// initialize the helper later if not skipped.

		// return mem to pool when done (big performance improvement)
		// only releases non nil allocations so it's safe to use before h.initialize.
		defer h.release()

		if c.EventRecordHelperCallback != nil {
			if err = c.EventRecordHelperCallback(h); err != nil {
				setError(fmt.Errorf("EventRecordHelperCallback failed: %w", err))
			}
		}
		// if event must be skipped we do not further process it
		if h.Flags.Skip {
			return
		}

		LogTrace("Decoding source", "source", lazyDecodeSource{h.TraceInfo.DecodingSource})

		// initialize record helper
		h.initialize()

		// prepareProperties_old is inneficient.
		if c.useOld {
			if err := h.prepareProperties_old(); err != nil {
				setError(fmt.Errorf("prepareProperties_old failed: %w", err))
				return
			}
		} else {
			if err := h.prepareProperties(); err != nil {
				setError(fmt.Errorf("prepareProperties failed: %w", err))
				return
			}
		}

		// running a hook before parsing event properties
		if c.EventPreparedCallback != nil {
			if err := c.EventPreparedCallback(h); err != nil {
				setError(fmt.Errorf("EventPreparedCallback failed: %w", err))
			}
		}

		// check if we must skip event after next hook
		if h.Flags.Skip || c.EventCallback == nil {
			return
		}

		var event *Event
		if event, err = h.buildEvent(); err != nil {
			setError(fmt.Errorf("buildEvent failed: %w", err))
		}

		if err := c.EventCallback(event); err != nil {
			setError(fmt.Errorf("EventCallback failed: %w", err))
		}
	} else {
		setError(fmt.Errorf("newEventRecordHelper failed: %w", err))
	}

	return
}

// TODO(tekert): selective close
// close closes the open handles and eventually waits for ProcessTrace goroutines
// to return if wait = true
func (c *Consumer) close_old_delete(wait bool) (lastErr error) {
	if c.closed {
		slog.Debug("Consumer already closed.")
		return
	}
	slog.Debug("Closing consumer...")

	c.tmu.Lock()
	// closing trace handles
	for _, t := range c.traces2 {
		slog.Debug("Closing handle for trace", "trace", t.TraceName)
		// if we don't wait for traces ERROR_CTX_CLOSE_PENDING is a valid error
		// The ERROR_CTX_CLOSE_PENDING code indicates that the CloseTrace function
		// call was successful; the ProcessTrace function will stop processing events
		// after it processes all previously-queued events
		// (ProcessTrace will not receive any new events after you call the CloseTrace function).
		if t.handle != 0 {
			var err error
			// Mark as closed to prevent further updates
			t.open = false
			if err = CloseTrace(t.handle); err != nil && err != ERROR_CTX_CLOSE_PENDING {
				lastErr = err
			}
			t.handle = 0
			close(t.done) // signal that the trace is closed
			t.done = nil  // closed, receivers already capture this.

			slog.Debug("handle closed", "trace", t.TraceName)
			if err == ERROR_CTX_CLOSE_PENDING {
				slog.Debug("ERROR_CTX_CLOSE_PENDING == true", "trace", t.TraceName, "message", err)
			}
		}
	}
	c.tmu.Unlock()

	slog.Debug("Waiting for ProcessTrace goroutines to end...")
	if wait {
		c.Wait()
	}
	slog.Debug("All ProcessTrace goroutines ended.")

	close(c.Events)
	c.closed = true
	slog.Debug("Events channel closed.")

	return
}

// TODO(tekert): selective close
// close closes the open handles and eventually waits for ProcessTrace goroutines
// to return if wait = true
func (c *Consumer) close(wait bool) (lastErr error) {
	if c.closed {
		slog.Debug("Consumer already closed.")
		return
	}
	slog.Debug("Closing consumer...")

	// closing trace handles
	c.traces.Range(func(key, value interface{}) bool {
		t := value.(*Trace)
		slog.Debug("Closing handle for trace", "trace", t.TraceName)
		// if we don't wait for traces ERROR_CTX_CLOSE_PENDING is a valid error
		// The ERROR_CTX_CLOSE_PENDING code indicates that the CloseTrace function
		// call was successful; the ProcessTrace function will stop processing events
		// after it processes all previously-queued events
		// (ProcessTrace will not receive any new events after you call the CloseTrace function).
		if t.handle != 0 {
			var err error

			// Mark as closed to prevent further updates
			c.tmu.Lock()
			t.open = false
			if err = CloseTrace(t.handle); err != nil && err != ERROR_CTX_CLOSE_PENDING {
				lastErr = err
			}
			t.handle = 0
			close(t.done) // signal that the trace is closed
			t.done = nil  // closed, receivers already capture this channel.
			c.tmu.Unlock()

			slog.Debug("handle closed", "trace", t.TraceName)
			if err == ERROR_CTX_CLOSE_PENDING {
				slog.Debug("ERROR_CTX_CLOSE_PENDING == true", "trace", t.TraceName, "message", err)
			}
		}
		return true
	})

	slog.Debug("Waiting for ProcessTrace goroutines to end...")
	if wait {
		c.Wait()
	}
	slog.Debug("All ProcessTrace goroutines ended.")

	close(c.Events)
	c.closed = true
	slog.Debug("Events channel closed.")

	return
}

// OpenTrace opens a Trace for consumption.
// All traces are opened with the new PROCESS_TRACE_MODE_EVENT_RECORD flag
func (c *Consumer) OpenTrace(name string) (err error) {
	c.tmu.Lock()
	defer c.tmu.Unlock()

	var traceHandle syscall.Handle
	ti := c.getOrAddTrace(name)
	ti.ctx = &traceContext{
		trace:    ti,
		consumer: c,
		ctxID:    contextID, // for context validation when trace closes.
	}

	// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_logfilea
	var loggerInfo *EventTraceLogfile = new(EventTraceLogfile)
	// PROCESS_TRACE_MODE_EVENT_RECORD to receive EventRecords (new format)
	// PROCESS_TRACE_MODE_RAW_TIMESTAMP don't convert TimeStamp member of EVENT_HEADER and EVENT_TRACE_HEADER to system time
	// PROCESS_TRACE_MODE_REAL_TIME to receive events in real time
	//loggerInfo.SetProcessTraceMode(PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP | PROCESS_TRACE_MODE_REAL_TIME)
	if !ti.realtime {
		loggerInfo.SetProcessTraceMode(PROCESS_TRACE_MODE_EVENT_RECORD)
	} else {
		loggerInfo.SetProcessTraceMode(PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME)
	}
	loggerInfo.BufferCallback = syscall.NewCallbackCDecl(c.bufferCallback)
	loggerInfo.Callback = syscall.NewCallbackCDecl(c.callback)
	loggerInfo.Context = uintptr(unsafe.Pointer(ti.ctx))
	// Use memory allocated already in the trace struct for the name
	if !ti.realtime {
		loggerInfo.LogFileName = ti.TraceNameW // We consume from the file.
	} else {
		// We use the session name to open the trace
		loggerInfo.LoggerName = ti.TraceNameW
	}

	if traceHandle, err = OpenTrace(loggerInfo); err != nil {
		return err
	}

	// Trace open
	ti.handle = syscall.Handle(traceHandle)
	ti.open = true
	ti.TraceLogFile = loggerInfo // Add trace logger info to opentrace return stats

	return nil
}

// FromSessions initializes the consumer from sessions
func (c *Consumer) FromSessions(sessions ...Session) *Consumer {
	for _, s := range sessions {
		c.InitFilters(s.Providers())
		c.getOrAddTrace(s.TraceName())
	}

	return c
}

// FromTraceNames initializes consumer from existing traces
func (c *Consumer) FromTraceNames(names ...string) *Consumer {
	for _, n := range names {
		c.getOrAddTrace(n)
	}
	return c
}

// InitFilters initializes event filtering from a Provider slice
func (c *Consumer) InitFilters(providers []Provider) {
	for _, p := range providers {
		c.Filter.Update(&p)
	}
}

// DefaultEventRecordHelperCallback is the default EventRecordCallback method applied
// to Consumer created with NewConsumer
func (c *Consumer) DefaultEventRecordHelperCallback(h *EventRecordHelper) error {
	h.Flags.Skip = !c.Filter.Match(h)
	return nil
}

// DefaultEventCallback is the default [Consumer.EventCallback] method applied
// to Consumer created with NewConsumer
// Receives parsed events and sends them to the Consumer.Events channel
func (c *Consumer) DefaultEventCallback(event *Event) (err error) {
	// we have to check again here as the lock introduced delay
	if c.ctx.Err() == nil {

		// if the event can be skipped we send it in a non-blocking way
		if event.Flags.Skippable {
			select {
			case c.Events <- event:
			default:
				c.Skipped.Add(1)
			}

			return
		}

		// if we cannot skip event we send it in a blocking way
		c.Events <- event
	}

	return
}

// Start starts the consumer, for each real time trace opened starts ProcessTrace in new goroutine
// Also opens any trace session not already opened for consumption.
func (c *Consumer) Start_old_delete() (err error) {
	// opening all traces that are not opened first,
	for name, trace := range c.traces2 {
		// if trace is already opened skip
		if trace.open {
			continue
		}

		if err = c.OpenTrace(name); err != nil {
			return fmt.Errorf("failed to open trace %s: %w", name, err)
		}
	}

	// opens a new goroutine for each trace and blocks.
	for name, trace := range c.traces2 {
		if trace.processing {
			continue
		}

		c.Add(1)
		go func(name string, trace *Trace) {
			defer c.Done()
			//c.processTrace(name, trace)
			c.processTraceWithTimeout(name, trace)
		}(name, trace)
	}

	return
}

// Start starts the consumer, for each real time trace opened starts ProcessTrace in new goroutine
// Also opens any trace session not already opened for consumption.
func (c *Consumer) Start() (err error) {
	// opening all traces that are not opened first,
	c.traces.Range(func(key, value interface{}) bool {
        name := key.(string)
        trace := value.(*Trace)
		// if trace is already opened skip
		if trace.open {
			return true // continue iteration
		}

		if err = c.OpenTrace(name); err != nil {
			err = fmt.Errorf("failed to open trace %s: %w", name, err)
			return false // stop iteration
		}
		return true
	})
	if err != nil {
        return err
    }

	// opens a new goroutine for each trace and blocks.
	c.traces.Range(func(key, value interface{}) bool {
        name := key.(string)
        trace := value.(*Trace)
		if trace.processing {
			return true // continue iteration
		}

		c.Add(1)
		go func(name string, trace *Trace) {
			defer c.Done()
			//c.processTrace(name, trace)
			c.processTraceWithTimeout(name, trace)
		}(name, trace)
		return true
	})

	return
}

func (c *Consumer) processTrace(name string, trace *Trace) {
	slog.Debug("Starting ProcessTrace", "trace", name)
	trace.processing = true
	// https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-processtrace
	// Won't return even if canceled until the session buffer is empty
	// (callback returns for every remaning event after CloseTrace or callbackBuffer returns 0)
	if err := ProcessTrace(&trace.handle, 1, nil, nil); err != nil {
		if err == ERROR_CANCELLED {
			// The consumer canceled processing by returning FALSE in their
			// BufferCallback function.
			slog.Info("ProcessTrace canceled", "trace", name, "err", err)
		} else {
			c.lastError = fmt.Errorf(
				"ProcessTrace failed: %w, handle: %v, LoggerName: %s", err, trace.handle, name)
		}
	}
	trace.processing = false
	trace.ctx = nil // context can be safely released now. (bufferCallback will not be called anymore)
	slog.Debug("ProcessTrace finished", "trace", name)
}

// Will return from the goroutine if ProcessTrace doesn't return after close.
// This will leave the ProcessTrace detached and processing events.
func (c *Consumer) processTraceWithTimeout(name string, trace *Trace) {
	traceDone := trace.done // capture the reference just in case
	pdone := make(chan struct{})
	// Start ProcessTrace in separate goroutine
	go func() {
		defer close(pdone)
		c.processTrace(name, trace)
	}()

	// Wait for either context cancellation or ProcessTrace return
	select {
	case <-c.ctx.Done():
		<-traceDone // wait for handle to be closed first.
		if c.closeTimeout != 0 {
			// Wait for ProcessTrace to finish naturally or timeout
			select {
			case <-pdone:
				// ProcessTrace completed before timeout
			case <-time.After(c.closeTimeout):
				slog.Warn("ProcessTrace did not complete within timeout", "trace", name)
				// Let goroutine continue but we return to unblock c.Wait()
				return
			}
		}
		// If forceTimeout == 0, wait for normal completion
		<-pdone
	case <-pdone:
		// ProcessTrace completed before Consumer stop (context close).
	}
}

// LastError returns the last error encountered by the consumer
func (c *Consumer) LastError() error {
	return c.lastError
}

// Stop blocks and waits for the ProcessTrace to empty it's buffer.
// Will CloseTrace all traces and wait for the ProcessTrace goroutines to return.
func (c *Consumer) Stop() (err error) {
	// ProcessTrace will exit only if the session buffer is empty.
	c.closeTimeout = 0
	c.cancel()
	return c.close(true)
}

// Call blocks and returns after timeout or if ProcessTrace goroutines finish earlier.
// Will CloseTrace all traces before returning.
//
// Delay to close ProcessTrace can happen if the etw buffer for ProcessTrace is full
// and the callback is not returning fast enough to empty the buffer or is blocked
// for some reason.
//
// timeout = -1 is as if Abort() was called.
// timeout = 0  is as if Stop() was called.
func (c *Consumer) StopWithTimeout(timeout time.Duration) (err error) {
	// ProcessTrace will exit only if the session buffer is empty.
	c.closeTimeout = timeout
	c.cancel()
	return c.close(true)
}

// Abort stops the Consumer and wont wait for the ProcessTrace calls
// to return, forcing the consumer to stop immediately, this can
// cause some remaining events to be lost.
// Will CloseTrace all traces and then detach ProcessTrace goroutines.
// goroutines stuck in ProcessTrace will be left processing events.
func (c *Consumer) Abort() (err error) {
	c.closeTimeout = -1
	c.cancel()
	return c.close(false)
}
