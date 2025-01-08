//go:build windows
// +build windows

package etw

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"sync"
	"syscall"
)

var (
	//rtLostEventGuid = MustParseGUIDFromString("{6A399AE0-4BC6-4DE9-870B-3657F8947E7E}") // don't use, not evaluated compile time.
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

type Consumer struct {
	sync.WaitGroup
	ctx          context.Context
	cancel       context.CancelFunc
	traceHandles []syscall.Handle // Opened trace handles
	lastError    error
	closed       bool

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

	// Trace names to open (used when specifying sessions to consume from)
	// true if the trace is open.
	// TODO(tekert): uhmm refactor this?
	traces map[string]bool

	// EventTraceLogfile used when opening the trace, filled with aditional info if the trace already opened.
	traceLoggerInfo map[syscall.Handle]*EventTraceLogfile

	LostEvents uint64

	Skipped uint64

	// TODO(tekert) For Testing, delete later
	useOld bool
}

// This is the logger info used to create the trace, after the trace is opened,
// this struct is filled with more data.
//
// This can also be updated on each BufferCallback // *NOTE(tekert): not enabled yet
func (c *Consumer) GetTraceLoggerInfo() *map[syscall.Handle]*EventTraceLogfile {

	return &c.traceLoggerInfo
}

// TODO(tekert): use or delete this
// Information about the Trace
type Trace struct {

	// Can be a user session name, manifest session name, GUID, or full file name path.
	Name string

	// Handle that OpenTrace returned.
	handle syscall.Handle

	// True is the trace is open
	opened bool

	// EventTraceLogfile that OpenTrace returned.
	// Use [OutputTraceLogFile()]
	outputTraceLogFile *EventTraceLogfile
}

// // *EventTraceLogfile used to open the trace, it's filled with additional info
// // more info at:  https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_logfilew
// // TRACE_LOGFILE_HEADER struct is also filled with more info about the trace
// func (c *Trace) OutputTraceLogFile() *EventTraceLogfile {
//     return c.outputTraceLogFile
// }

// Uses the old version using tdhGetProperty (inneficient)
func NewConsumer_old(ctx context.Context) (c *Consumer) {
	c = NewConsumer(ctx)

	c.useOld = true

	return c
}

// NewConsumer creates a new Consumer to consume ETW
func NewConsumer(ctx context.Context) (c *Consumer) {
	c = &Consumer{
		traceHandles:    make([]syscall.Handle, 0, 64),
		traces:          make(map[string]bool),
		Filter:          NewProviderFilter(),
		Events:          make(chan *Event, 4096),
		traceLoggerInfo: make(map[syscall.Handle]*EventTraceLogfile),
	}

	c.ctx, c.cancel = context.WithCancel(ctx)
	c.EventRecordHelperCallback = c.DefaultEventRecordHelperCallback
	c.EventCallback = c.DefaultEventCallback

	return c
}

func (c *Consumer) bufferCallback(e *EventTraceLogfile) uintptr {
	// TODO(tekert): get updates stats from EventTraceLogfile in a performant way.
	if c.ctx.Err() != nil {
		// if the consumer has been stopped we
		// don't process event records anymore
		return 0
	}
	// we keep processing event records
	return 1
}

// Called when ProcessTrace gets an event record.
// This is always called sequentially on the same thread of ProcessTrace,
// so it may block other events. Only one event is processed at a time.
func (c *Consumer) callback(er *EventRecord) (rc uintptr) {
	var event *Event

	// Skips the event if it is the event trace header. Log files contain this event
	// but real-time sessions do not. The event contains the same information as
	// the EVENT_TRACE_LOGFILE.LogfileHeader member that you can access when you open
	// the trace.
	if er.EventHeader.ProviderId.Equals(EventTraceGuid) &&
		er.EventHeader.EventDescriptor.Opcode == EVENT_TRACE_TYPE_INFO {
		// Skip this event.
		return
	}

	if er.EventHeader.ProviderId.Equals(rtLostEventGuid) {
		c.LostEvents++
	}

	// calling EventHeaderCallback if possible
	if c.EventRecordCallback != nil {
		if !c.EventRecordCallback(er) {
			return
		}
	}

	// we get the consumer from EventRecord.UserContext, NOTE(tekert): where? i don't see it
	// Parse TRACE_EVENT_INFO from the event record
	if h, err := newEventRecordHelper(er); err == nil {
		// initialize the helper later if not skipped.

		defer h.release() // return mem to pool when done

		if c.EventRecordHelperCallback != nil {
			if err = c.EventRecordHelperCallback(h); err != nil {
				c.lastError = fmt.Errorf("EventRecordHelperCallback failed: %w", err)
			}
		}
		// if event must be skipped we do not further process it
		if h.Flags.Skip {
			return
		}

		slog.Debug("Decoding source", "source", lazyDecodeSource{h.TraceInfo.DecodingSource})

		// initialize record helper
		h.initialize()

		//! TODO(tekert): prepareProperties check for WPP events,
		// prepareProperties_old is inneficient and uses old funcions.
		if c.useOld {
			if err := h.prepareProperties_old(); err != nil {
				c.lastError = fmt.Errorf("prepareProperties_old failed: %w", err)
				return
			}
		} else {
			if err := h.prepareProperties(); err != nil {
				c.lastError = fmt.Errorf("prepareProperties failed: %w", err)
				return
			}
		}

		// running a hook before parsing event properties
		if c.EventPreparedCallback != nil {
			if err := c.EventPreparedCallback(h); err != nil {
				c.lastError = fmt.Errorf("EventPreparedCallback failed: %w", err)
			}
		}

		// check if we must skip event after next hook
		if h.Flags.Skip || c.EventCallback == nil {
			return
		}

		if event, err = h.buildEvent(); err != nil {
			c.lastError = fmt.Errorf("buildEvent failed: %w", err)
		}

		if err := c.EventCallback(event); err != nil {
			c.lastError = fmt.Errorf("EventCallback failed: %w", err)
		}
	}

	return
}

// close closes the Consumer and eventually waits for ProcessTraces calls
// to end
func (c *Consumer) close(wait bool) (lastErr error) {
	if c.closed {
		return
	}

	// closing trace handles
	for _, h := range c.traceHandles {
		// if we don't wait for traces ERROR_CTX_CLOSE_PENDING is a valid error
		if err := CloseTrace(h); err != nil && err != ERROR_CTX_CLOSE_PENDING {
			lastErr = err
		}
	}

	if wait {
		c.Wait()
	}

	close(c.Events)
	c.closed = true

	return
}

// Open a new trace to consume from a .etl compatible file format
// This file acts like a provider, so no need to setup any provider or sessions(buffers)
// All traces are opened with the new PROCESS_TRACE_MODE_EVENT_RECORD flag
func (c *Consumer) OpenTraceFile(filename string) (err error) {
	var traceHandle syscall.Handle

	var loggerInfo *EventTraceLogfile = new(EventTraceLogfile)
	loggerInfo.SetProcessTraceMode(PROCESS_TRACE_MODE_EVENT_RECORD)
	loggerInfo.BufferCallback = syscall.NewCallbackCDecl(c.bufferCallback)
	loggerInfo.Callback = syscall.NewCallbackCDecl(c.callback)

	// We consume from the file.
	if loggerInfo.LogFileName, err = syscall.UTF16PtrFromString(filename); err != nil {
		return err
	}

	if traceHandle, err = OpenTrace(loggerInfo); err != nil {
		return err
	}

	// Trace open,
	// TODO(tekert): make new struct maybe? Trace, enabled, open, is file, is realtime, etc.
	c.traces[filename] = true
	// Add trace logger info to opentrace return stats
	c.traceLoggerInfo[traceHandle] = loggerInfo

	c.traceHandles = append(c.traceHandles, syscall.Handle(traceHandle))
	return nil
}

// OpenTraceRT opens a Real Time Session Trace using the flag (PROCESS_TRACE_MODE_REAL_TIME)
// All traces are opened with the new PROCESS_TRACE_MODE_EVENT_RECORD flag
func (c *Consumer) OpenTraceRT(name string) (err error) {
	var traceHandle syscall.Handle

	//loggerInfo := c.newRealTimeLogfile()
	var loggerInfo *EventTraceLogfile = new(EventTraceLogfile)
	// PROCESS_TRACE_MODE_EVENT_RECORD to receive EventRecords (new format)
	// PROCESS_TRACE_MODE_RAW_TIMESTAMP don't convert TimeStamp member of EVENT_HEADER and EVENT_TRACE_HEADER converted to system time
	// PROCESS_TRACE_MODE_REAL_TIME to receive events in real time
	//loggerInfo.SetProcessTraceMode(PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP | PROCESS_TRACE_MODE_REAL_TIME)
	loggerInfo.SetProcessTraceMode(PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME)
	loggerInfo.BufferCallback = syscall.NewCallbackCDecl(c.bufferCallback)
	loggerInfo.Callback = syscall.NewCallbackCDecl(c.callback)

	// We use the session name to open the trace
	if loggerInfo.LoggerName, err = syscall.UTF16PtrFromString(name); err != nil {
		return err
	}

	if traceHandle, err = OpenTrace(loggerInfo); err != nil {
		return err
	}

	// Trace open
	c.traces[name] = true
	// Add trace logger info to opentrace return stats
	c.traceLoggerInfo[traceHandle] = loggerInfo

	c.traceHandles = append(c.traceHandles, syscall.Handle(traceHandle))
	return nil
}

// FromSessions initializes the consumer from sessions
func (c *Consumer) FromSessions(sessions ...Session) *Consumer {

	for _, s := range sessions {
		c.InitFilters(s.Providers())
		c.traces[s.TraceName()] = false
	}

	return c
}

// FromTraceNames initializes consumer from existing traces
func (c *Consumer) FromTraceNames(names ...string) *Consumer {
	for _, n := range names {
		c.traces[n] = false
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

// DefaultEventCallback is the default EventCallback method applied
// to Consumer created with NewConsumer
func (c *Consumer) DefaultEventCallback(event *Event) (err error) {
	// we have to check again here as the lock introduced delay
	if c.ctx.Err() == nil {

		// if the event can be skipped we send it in a non-blocking way
		if event.Flags.Skippable {
			select {
			case c.Events <- event:
			default:
				c.Skipped++
			}

			return
		}

		// if we cannot skip event we send it in a blocking way
		c.Events <- event
	}

	return
}

// Start starts the consumer, for each real time trace opened starts ProcessTrace in new goroutine
// Also opens any trace session not already opened.
func (c *Consumer) Start() (err error) {

	// opening all traces that are not opened first, key = trace name, value = opened state
	for n, open := range c.traces {
		// if trace is already opened skip
		if open {
			continue
		}

		if err = c.OpenTraceRT(n); err != nil {
			return fmt.Errorf("failed to open trace %s: %w", n, err)
		}
	}

	for i := range c.traceHandles {
		i := i
		c.Add(1)
		go func() {
			defer c.Done()
			// ProcessTrace can contain only ONE handle to a real-time processing session
			// src: https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-processtrace
			if err := ProcessTrace(&c.traceHandles[i], 1, nil, nil); err != nil {
				loggerName := UTF16PtrToString(c.traceLoggerInfo[c.traceHandles[i]].LoggerName)
				c.lastError = fmt.Errorf(
					"ProcessTrace failed: %w, handle: %v, LoggerName: %s", err, c.traceHandles[i], loggerName)
			}
		}()
	}

	return
}

// LastError returns the last error encountered by the consumer
func (c *Consumer) LastError() error {
	return c.lastError
}

// Stop stops the Consumer and waits for the ProcessTrace calls
// to be terminated
func (c *Consumer) Stop() (err error) {
	// calling context cancel function
	c.cancel()
	return c.close(true)
}

// Abort stops the Consumer and doesn't waits for the ProcessTrace calls
// to be terminated, forcing the consumer to stop immediately, this can
// cause some events to be lost.
func (c *Consumer) Abort() (err error) {
	// calling context cancel function
	c.cancel()
	return c.close(false)
}
