//go:build windows
// +build windows

package etw

import (
	"syscall"
	"unsafe"
)

// KERNEL_LOGGER_NAME
const (
	NtKernelLogger = "NT Kernel Logger"
	//  0x9e814aad, 0x3204, 0x11d2, 0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39
)

// https://learn.microsoft.com/en-us/windows/win32/etw/msnt-systemtrace
var (
	//systemTraceControlGuid = MustParseGUIDFromString("{9E814AAD-3204-11D2-9A82-006008A86939}")
	systemTraceControlGuid = &GUID{ /* {9E814AAD-3204-11D2-9A82-006008A86939} */
		Data1: 0x9e814aad,
		Data2: 0x3204,
		Data3: 0x11d2,
		Data4: [8]byte{0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39},
	}
)

// Trace Session interface
type Session interface {
	TraceName() string
	Providers() []Provider
	IsKernelSession() bool
}

// Real time Trace Session
type RealTimeSession struct {
	properties    *EventTraceProperties2
	sessionHandle syscall.Handle

	traceName string
	providers []Provider
}

func (p *RealTimeSession) IsKernelSession() bool {
	return p.traceName == NtKernelLogger ||
		(p.properties.LogFileMode&EVENT_TRACE_SYSTEM_LOGGER_MODE) != 0
}

// NewRealTimeSession creates a new ETW session to receive events
// in real time
func NewRealTimeSession(name string) (s *RealTimeSession) {
	s = &RealTimeSession{}
	s.properties = NewRealTimeEventTraceSessionProperties(name)
	s.traceName = name
	s.providers = make([]Provider, 0)
	return
}

// Only use this if the providers that will be enabled are not kernel providers
//
// NewPagedRealTimeSession creates a new ETW session to receive events
// in real time that uses paged memory.
// This setting is recommended so that events do not use up the nonpaged memory.
// Nonpaged buffers use nonpaged memory for buffer space.
// Because nonpaged buffers are never paged out, a logging session performs well.
// Using pageable buffers is less resource-intensive.
// Kernel-mode providers and system loggers cannot log events to sessions that specify this logging mode.
func NewPagedRealTimeSession(name string) (s *RealTimeSession) {
	s = NewRealTimeSession(name)
	s.properties.LogFileMode |= EVENT_TRACE_USE_PAGED_MEMORY
	return
}

// NewKernelRealTimeSession creates a new ETW session to receive
// NT Kernel Logger events in real time (only one session can be running at any time)
//
// Flags: https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties EnableFlags section
//
// More info at: https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-the-nt-kernel-logger-session
func NewKernelRealTimeSession(flags ...uint32) (p *RealTimeSession) {
	p = NewRealTimeSession(NtKernelLogger)
	// guid must be set for Kernel Session
	p.properties.Wnode.Guid = *systemTraceControlGuid
	for _, flag := range flags {
		p.properties.EnableFlags |= flag
	}
	return
}

// * NOTE needs Windows 10 SDK build 20348 or later
// new way to enable kernel (now system) providers
// Not used for now (made private)
//
// https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-a-systemtraceprovider-session
//
// # Starting a SystemTraceProvider Session using guids and keywords
//
// How to use it:
//   - GUIDs and Keywords defined here: https://learn.microsoft.com/en-us/windows/win32/etw/system-providers
//   - Write the keywords you want and put them in MustParseProvider() wich go to EnableTraceEx2
//
// NOTE* The keywords are too new and are not defined on most systems.
func newSystemTraceProviderSession(name string) (s *RealTimeSession) {
	s = NewRealTimeSession(name)
	s.properties.LogFileMode |= EVENT_TRACE_SYSTEM_LOGGER_MODE
	return
}

func NewRealTimeEventTraceSessionProperties(logSessionName string) *EventTraceProperties2 {
	sessionProperties, size := NewEventTraceSessionPropertiesV2(logSessionName)

	// Necessary fields for SessionProperties struct
	sessionProperties.Wnode.BufferSize = size // this is optimized by ETWframework
	sessionProperties.Wnode.Guid = GUID{}     //To set
	sessionProperties.Wnode.ClientContext = 1 // QPC
	// *NOTE(tekert) should this be WNODE_FLAG_TRACED_GUID instead of WNODE_FLAG_ALL_DATA?
	sessionProperties.Wnode.Flags = WNODE_FLAG_TRACED_GUID | WNODE_FLAG_VERSIONED_PROPERTIES
	sessionProperties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE
	sessionProperties.LogFileNameOffset = 0
	// ETW event can be up to 64KB size so if the buffer size is not at least
	// big enough to contain such an event, the event will be lost
	// source: https://docs.microsoft.com/en-us/message-analyzer/specifying-advanced-etw-session-configuration-settings
	sessionProperties.BufferSize = 64
	sessionProperties.LoggerNameOffset = uint32(unsafe.Sizeof(EventTraceProperties2{}))

	return sessionProperties
}

// IsStarted returns true if the session is already started
func (s *RealTimeSession) IsStarted() bool {
	return s.sessionHandle != 0
}

// Start starts the session
func (s *RealTimeSession) Start() (err error) {
	var u16TraceName *uint16

	if u16TraceName, err = syscall.UTF16PtrFromString(s.traceName); err != nil {
		return err
	}

	if !s.IsStarted() {

		if s.IsKernelSession() {
			// Remove EVENT_TRACE_USE_PAGED_MEMORY flag from session properties
			s.properties.LogFileMode &= ^uint32(EVENT_TRACE_USE_PAGED_MEMORY)
		}

		if err = StartTrace(&s.sessionHandle, u16TraceName, s.properties); err != nil {
			// we handle the case where the trace already exists
			if err == ERROR_ALREADY_EXISTS {
				// we have to use a copy of properties as ControlTrace modifies
				// the structure and if we don't do that we cannot StartTrace later
				prop := *s.properties
				// we close the trace first
				ControlTrace(0, u16TraceName, &prop, EVENT_TRACE_CONTROL_STOP)
				return StartTrace(&s.sessionHandle, u16TraceName, s.properties)
			}
			return
		}
	}

	return
}

// EnableProvider enables the trace session using [EnableTraceEx2] to receive events from a given provider
func (s *RealTimeSession) EnableProvider(prov Provider) (err error) {
	var guid *GUID

	// If the trace is not started yet we have to start it
	// otherwise we cannot enable provider
	if !s.IsStarted() {
		if err = s.Start(); err != nil {
			return
		}
	}

	guid = &prov.GUID

	params := EnableTraceParameters{
		Version: 2,
		// Does not seem to bring valuable information
		//EnableProperty: EVENT_ENABLE_PROPERTY_PROCESS_START_KEY,
	}

	if len(prov.Filter) > 0 {
		fds := prov.BuildFilterDesc()
		if len(fds) > 0 {
			params.EnableFilterDesc = (*EventFilterDescriptor)(unsafe.Pointer(&fds[0]))
			params.FilterDescCount = uint32(len(fds))
		}
	}

	if err = EnableTraceEx2(
		s.sessionHandle,
		guid,
		EVENT_CONTROL_CODE_ENABLE_PROVIDER,
		prov.EnableLevel,
		prov.MatchAnyKeyword,
		prov.MatchAllKeyword,
		0,
		&params,
	); err != nil {
		return
	}

	s.providers = append(s.providers, prov)

	return
}

// TraceName implements Session interface
func (s *RealTimeSession) TraceName() string {
	return s.traceName
}

// Providers implements Session interface
func (s *RealTimeSession) Providers() []Provider {
	return s.providers
}

// Stop stops the session
func (s *RealTimeSession) Stop() error {
	return ControlTrace(s.sessionHandle, nil, s.properties, EVENT_TRACE_CONTROL_STOP)
}
