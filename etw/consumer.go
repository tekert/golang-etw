//go:build windows

package etw

import (
	"context"
	"fmt"
	"reflect"
	"runtime"
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
	ctx    context.Context
	cancel context.CancelFunc
	closed bool

	tmu    sync.RWMutex // Protect trace updates
	traces sync.Map     // Traces Information

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
	// errors returned by this callback will be logged
	// to skip further processing of the event set EventRecordHelper.Flags.Skip = true
	EventRecordHelperCallback func(*EventRecordHelper) error

	// [3] Callback executed after event properties got prepared (step before parsing).
	// Properties are not parsed yet and this is the right place to filter
	// events based only on some properties.
	// NB: events skipped in EventRecordCallback never reach this function
	// errors returned by this callback will be logged
	// to skip further processing of the event set EventRecordHelper.Flags.Skip = true
	EventPreparedCallback func(*EventRecordHelper) error

	// [4] Callback executed after the event got parsed and defines what to do
	// with the event (printed, sent to a channel ...)
	// errors returned by this callback will be logged
	EventCallback func(*Event) error

	Filter EventFilter

	// The total number of event's lost.
	LostEvents atomic.Uint64

	// The total number of events that were skipped.
	Skipped atomic.Uint64

	// to force stop the Consumer ProcessTrace if buffer takes too long to empty.
	// stores timeout in nanoseconds
	closeTimeout time.Duration // stores timeout in nanoseconds

	// EventsBatch channel configutation.
	Events *EventBuffer
}

type traceContext struct {
	trace    *Trace
	consumer *Consumer
}

// Helper function to get the traceContext from the UserContext
// These are used from ETW callbacks to get a reference back to our context.
func (er *EventRecord) getUserContext() *traceContext {
	return (*traceContext)(unsafe.Pointer(er.UserContext))
}
func (e *EventTraceLogfile) getContext() *traceContext {
	return (*traceContext)(unsafe.Pointer(e.Context))
}

// NewConsumer creates a new Consumer to consume ETW
func NewConsumer(ctx context.Context) (c *Consumer) {
	c = &Consumer{
		Filter: NewProviderFilter(),
		Events: NewEventBuffer(),
	}

	c.ctx, c.cancel = context.WithCancel(ctx)
	c.EventRecordHelperCallback = c.DefaultEventRecordHelperCallback
	c.EventCallback = c.DefaultEventCallback

	return c
}

// // Returns a deep copy of the struct, so it can be safely used after trace is closed.
// // The original it's no longer valid when the Consumer is stopped. (Trace handle closed)
// // When the trace is closed, this struct is cloned so it can be returned to the user.
// func (c *Consumer) cloneTraceLogfile(tname string) (et *EventTraceLogfile) {
// 	if v, ok := c.traces.Load(tname); ok {
// 		trace := v.(*Trace)
// 		c.tmu.RLock()
// 		et = trace.traceLogFile.Clone()
// 		c.tmu.RUnlock()
// 	}
// 	return
// }

// gets or creates a new one if it doesn't exist
func (c *Consumer) getOrAddTrace(traceName string) *Trace {
	actual, _ := c.traces.LoadOrStore(traceName, newTrace(traceName))
	return actual.(*Trace)
}

// Returns the current traces info
func (c *Consumer) GetTraces() map[string]*Trace {
	traces := make(map[string]*Trace)
	// create map from sync.Map
	c.traces.Range(func(key, value interface{}) bool {
		t := value.(*Trace)
		c.tmu.RLock()
		tc := t
		c.tmu.RUnlock()
		traces[key.(string)] = tc
		return true
	})
	return traces
}

// GetTrace retrieves a trace by its name from the consumer's trace collection.
// It returns a pointer to the Trace and a boolean indicating whether the trace was found.
func (c *Consumer) GetTrace(tname string) (t *Trace, ok bool) {
	if v, ok := c.traces.Load(tname); ok {
		trace := v.(*Trace)
		c.tmu.RLock()
		t = trace
		c.tmu.RUnlock()
		return t, ok
	}
	return nil, false
}

// https://learn.microsoft.com/en-us/windows/win32/etw/rt-lostevent
// EventType{32, 33, 34}, EventTypeName{"RTLostEvent", "RTLostBuffer", "RTLostFile"}]
func (c *Consumer) handleLostEvent(e *EventRecord) {
	var traceInfo *TraceEventInfo
	var err error
	if traceInfo, _, err = e.GetEventInformation(); err == nil {
		u := e.getUserContext() // No need to protect with mutex here.
		switch traceInfo.EventDescriptor.Opcode {
		case 32:
			// The RTLostEvent event type indicates that one or more events were lost.
			u.trace.RTLostEvents.Add(1)
		case 33:
			// The RTLostBuffer event type indicates that one or more buffers were lost
			u.trace.RTLostBuffer.Add(1)
		case 34:
			// The RTLostFile indicates that the backing file used by the AutoLogger
			// to capture events was lost.
			u.trace.RTLostFile.Add(1)
		default:
			log.Debug().Uint8("opcode", traceInfo.EventDescriptor.Opcode).
				Msg("Invalid opcode for lost event")
		}
	}
	c.LostEvents.Add(1)
}

// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nc-evntrace-pevent_trace_buffer_callbacka
//
// ETW event consumers implement this function to receive statistics about each buffer
// of events that ETW delivers during a trace processing Session.
// ETW calls this function after the events for each Trace Session buffer are delivered.
// The pointer received is the same on each subsequent call for each trace.
// The pointer received here is not the same one used in OpenTrace.
func (c *Consumer) bufferCallback(e *EventTraceLogfile) uintptr {
	// ensure userctx is not garbage collected after CloseTrace or it crashes invalid mem.
	userctx := e.getContext()

	c.tmu.Lock()
	if userctx != nil && userctx.trace.open {
		userctx.trace.traceLogFileBuffer = e
	}
	c.tmu.Unlock()

	if c.ctx.Err() != nil {
		// if the consumer has been stopped we
		// don't process event records anymore
		// return 0 to stop ProcessTrace
		log.Trace().Msg("bufferCallback: Context canceled, stopping ProcessTrace...")

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
			er.getUserContext().trace.ErrorEvents.Add(1) // safe here.
		}
		c.lastError = err
		//log.Debug().Err(err).Msg("callback error")
	}

	// Skips the event if it is the event trace header. Log files contain this event
	// but real-time sessions do not. The event contains the same information as
	// the EVENT_TRACE_LOGFILE.LogfileHeader member that you can access when you open
	// the trace.
	if er.EventHeader.ProviderId.Equals(EventTraceGuid) &&
		er.EventHeader.EventDescriptor.Opcode == EVENT_TRACE_TYPE_INFO {
		log.Debug().Interface("event", er).Msg("Skipping EventTraceGuid event")
		// Skip this event.
		return
	}

	if er.EventHeader.ProviderId.Equals(rtLostEventGuid) {
		c.handleLostEvent(er)
		return
	}

	// calling EventHeaderCallback if possible
	if c.EventRecordCallback != nil {
		if !c.EventRecordCallback(er) {
			return
		}
	}

	// TODO: some MOF events will not have a TRACE_EVENT_INFO

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

		// initialize record helper
		h.initialize()

		if err := h.prepareProperties(); err != nil {
			setError(fmt.Errorf("prepareProperties failed: %w", err))
			return
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
func (c *Consumer) close(wait bool) (lastErr error) {
	if c.closed {
		log.Debug().Msg("Consumer already closed.")
		return
	}
	log.Debug().Msg("Closing consumer...")

	// closing trace handles
	c.traces.Range(func(key, value interface{}) bool {
		t := value.(*Trace)
		log.Debug().Str("trace", t.TraceName).Msg("Closing handle for trace")
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
			c.tmu.Unlock()

			log.Debug().Str("trace", t.TraceName).Msg("handle closed")
			if err == ERROR_CTX_CLOSE_PENDING {
				log.Debug().Str("trace", t.TraceName).Err(err).Msg("ERROR_CTX_CLOSE_PENDING == true")
			}
		}
		return true
	})

	log.Debug().Msg("Waiting for ProcessTrace goroutines to end...")
	if wait {
		c.Wait()
	}
	log.Debug().Msg("All ProcessTrace goroutines ended.")

	c.Events.close()
	log.Debug().Msg("Events channel closed.")

	c.closed = true

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
	}

	// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_logfilea
	var loggerInfo *EventTraceLogfile = &ti.traceLogFile
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

	return nil
}

// // Gets the properties of a trace session with traceName in utf16
// // useful for checking an existing TraceLogFile logName.
// // same as [Trace.QueryTrace] but for traceNameW in utf16
// func (c *Consumer) QueryTraceW(traceNameW *uint16) (prop *EventTracePropertyData2, err error) {
// 	if traceNameW == nil {
// 		return nil, fmt.Errorf("traceNameW is nil")
// 	}

// 	c.traces.Range(func(key, value interface{}) bool {
// 		t := value.(*Trace)

// 		// if pointer points to the same location, same name.
// 		if (traceNameW == t.TraceNameW) {
// 			prop, err = t.QueryTrace()
// 			return false
// 		}

// 		// Compare UTF16 strings until null terminator
// 		for i := 0; ; i++ {
// 			c1 := *(*uint16)(unsafe.Add(unsafe.Pointer(traceNameW), i*2))
// 			c2 := *(*uint16)(unsafe.Add(unsafe.Pointer(t.TraceNameW), i*2))

// 			if c1 != c2 {
// 				return true // continue Range
// 			}
// 			if c1 == 0 && c2 == 0 { // null terminator
// 				prop, err = t.QueryTrace()
// 				return false // stop Range
// 			}
// 		}
// 	})

// 	return
// }

// same as [Trace.QueryTrace] but using string traceName
func (c *Consumer) QueryTrace(traceName string) (prop *EventTracePropertyData2, err error) {
	value, ok := c.traces.Load(traceName)
	if !ok {
		return nil, fmt.Errorf("trace %s not found", traceName)
	}
	t := value.(*Trace)
	return t.QueryTrace()
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

// inneficient. (i almost rewrote every single function in this fork...)
// DefaultEventCallback is the default [Consumer.EventCallback] method applied
// to Consumer created with NewConsumer
// Receives parsed events and sends them to the Consumer.Events channel.
//
// func (c *Consumer) DefaultEventCallback_old(event *Event) (err error) {
// 	// we have to check again here as the lock introduced delay
// 	if c.ctx.Err() == nil {
// 		// if the event can be skipped we send it in a non-blocking way
// 		if event.Flags.Skippable {
// 			select {
// 			case c.Events <- event:
// 			default:
// 				c.Skipped.Add(1)
// 				event.Release()
// 			}
// 			return
// 		}
// 		// if we cannot skip event we send it in a blocking way
// 		c.Events <- event
// 	}
// 	return
// }

// Will only work while using the [DefaultEventCallback] method.
// This is an example of how to read events with channels, 6% overhead
// vs reading events from custom EventCallback function
//
// ProcessEvents processes events from the Consumer.EventsBatch channel.
// This function blocks.
// The function fn is called for each event.
// To cancel it just call [Consumer.Stop()] or close the context.
//
// For the func(*Event) error: return err to unblock.
//
//	go func() {
//		c.ProcessEvents(func(e *etw.Event) {
//			_ = e
//		})
//	}()
//
// or
//
//	err := c.ProcessEvents(func(e *Event) error {
//	    _ = e
//	   if someCondition {
//	       return fmt.Errorf("error") // stops processing
//	   }
//	   return nil // continues processing
//	})
func (c *Consumer) ProcessEvents(fn any) error {
	switch cb := fn.(type) {
	case func(*Event):
		// Simple callback without return
		for batch := range c.Events.Channel {
			for _, e := range batch {
				cb(e)
				e.Release()
			}
		}
	case func(*Event) error:
		// Callback with bool return to control flow
		for batch := range c.Events.Channel {
			for _, e := range batch {
				if err := cb(e); err != nil {
					e.Release()
					return err
				}
				e.Release()
			}
		}
	}
	return nil
}

// DefaultEventCallback is the default [Consumer.EventCallback] method applied
// to Consumer created with NewConsumer
// Receives parsed events and sends them in batches to the Consumer.EventsBatch channel.
//
// Sends event in batches to the Consumer.EventsBatch channel. (better performance)
// After 200ms have passed or after 20 events have been queued by default.
func (c *Consumer) DefaultEventCallback(event *Event) error {
	if c.ctx.Err() == nil {
		c.Events.Send(event) // blocks if channel is full.
	}
	return nil
}

// Start starts the consumer, for each real time trace opened starts ProcessTrace in new goroutine
// Also opens any trace session not already opened for consumption.
func (c *Consumer) Start() (err error) {
	// opening all traces that are not opened first,
	c.traces.Range(func(key, value any) bool {
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
	c.traces.Range(func(key, value any) bool {
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
	// Lock the goroutine to the OS thread (callback will also be an os thread)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	goroutineID := getGoroutineID()
	log.Info().Str("trace", name).Interface("goroutineID", goroutineID).Msg("Starting processTrace")

	trace.processing = true
	// https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-processtrace
	// Won't return even if canceled (CloseTrace or callbackBuffer returning 0),
	// until the session buffer is empty, meaning the defined callback has to return
	// for every remaining event in the buffer, then ProcessTrace will unblock.
	// This must be to make sure all events are processed before  the user closes the handle.
	if err := ProcessTrace(&trace.handle, 1, nil, nil); err != nil {
		if err == ERROR_CANCELLED {
			// The consumer canceled processing by returning FALSE in their
			// BufferCallback function.
			log.Info().Str("trace", name).Err(err).Msg("ProcessTrace canceled")
		} else {
			c.lastError = fmt.Errorf(
				"ProcessTrace failed: %w, handle: %v, LoggerName: %s", err, trace.handle, name)
			log.Error().Err(c.lastError).Msg("ProcessTrace failed")
		}
	}
	trace.processing = false
	trace.ctx = nil // context can be safely released now. (bufferCallback will not be called anymore)
	log.Debug().Str("trace", name).Msg("ProcessTrace finished")
}

// Will return from the goroutine if ProcessTrace doesn't return after close.
// This will leave the ProcessTrace detached and flushing events.
func (c *Consumer) processTraceWithTimeout(name string, trace *Trace) {
	//traceDone := trace.done // capture the reference just in case
	pdone := make(chan struct{})
	// Start ProcessTrace in separate goroutine
	go func() {
		defer close(pdone)
		c.processTrace(name, trace)
	}()

	// Wait for either context cancellation or ProcessTrace return
	select {
	case <-c.ctx.Done():
		//<-traceDone // wait for handle to be closed first.
		if c.closeTimeout != 0 {
			// Wait for ProcessTrace to finish naturally or timeout
			select {
			case <-pdone:
				// ProcessTrace completed before timeout
			case <-time.After(c.closeTimeout):
				log.Warn().Str("trace", name).Msg("ProcessTrace did not complete within timeout")
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
// Delays to close ProcessTrace can happen if the etw buffer for ProcessTrace is full
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

// Abort stops the Consumer and won't wait for the ProcessTrace calls
// to return, forcing the consumer to stop immediately, this can
// cause some remaining events to be lost.
// Will CloseTrace all traces and then detach ProcessTrace goroutines.
// goroutines stuck in ProcessTrace will be left processing events.
func (c *Consumer) Abort() (err error) {
	c.closeTimeout = -1
	c.cancel()
	return c.close(false)
}
