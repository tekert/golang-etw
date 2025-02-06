package etw

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/tekert/golang-etw/etw/pkg/hexf"
)

// This is called only for static analysis purposes, so it's not used often
// enconding/json is slow but it does the job

// JsonLogfile is a JSON-safe version of EventTraceLogfile
type JsonLogfile struct {
	LogFileName   string
	LoggerName    string
	CurrentTime   time.Time
	BuffersRead   uint32
	ProcessMode   uint32 // From Union1
	LogfileHeader JsonLogHeader
	BufferSize    uint32
	Filled        uint32
	EventsLost    uint32
	IsKernelTrace uint32
}

type JsonLogHeader struct {
	BufferSize         string
	Version            string
	ProviderVersion    string
	NumberOfProcessors uint32
	EndTime            time.Time
	TimerResolution    uint32
	MaxFileSize        uint32
	LogFileMode        string
	BuffersWritten     uint32
	StartBuffers       uint32 // From Union2[0-3]
	PointerSize        uint32 // From Union2[4-7]
	EventsLost         uint32 // From Union2[8-11]
	CpuSpeedInMHz      uint32 // From Union2[12-15]
	LoggerName         string `json:",omitempty"`
	LogFileName        string `json:",omitempty"`
	TimeZone           JsonTimeZoneInfo
	BootTime           time.Time
	PerfFreq           int64
	StartTime          time.Time
	ReservedFlags      uint32
	BuffersLost        uint32
}

type JsonTime time.Time
type JsonTimeZoneInfo struct {
	Bias         int32
	StandardName string
	StandardDate JsonTime `json:",omitempty"`
	StandardBias int32    `json:",omitempty"`
	DaylightName string
	DaylightDate JsonTime `json:",omitempty"`
	DaylightBias int32    `json:",omitempty"`
}

func (t JsonTime) MarshalJSON() ([]byte, error) {
	tt := time.Time(t)
	if tt.IsZero() {
		return []byte("null"), nil // Return null for zero time
	}

	// Format time directly to avoid recursive json.Marshal
	b := make([]byte, 0, 26) // len(`"2006-01-02T15:04:05Z07:00"`)
	b = append(b, '"')
	b = tt.AppendFormat(b, time.RFC3339)
	b = append(b, '"')
	return b, nil
}

// MarshalJSON implements json.Marshaler for EventTraceLogfile
func (etl *EventTraceLogfile) MarshalJSON() ([]byte, error) {
	safe, err := etl.ToJSON()
	if err != nil {
		return nil, err
	}
	return json.Marshal(safe) // slow, but this is not used repeatedly (if it is remove this)
}

// ToJSON converts TraceLogfileHeader to a JSON-safe struct
func (h *TraceLogfileHeader) ToJSON() (JsonLogHeader, error) {
	if h == nil {
		return JsonLogHeader{}, nil
	}

	major, minor, sub, subMinor := h.GetVersion()

	return JsonLogHeader{
		BufferSize:         fmt.Sprintf("%d KB", h.BufferSize),
		Version:            fmt.Sprintf("%d.%d.%d.%d", major, minor, sub, subMinor),
		ProviderVersion:    fmt.Sprintf("Build version: %d", h.ProviderVersion),
		NumberOfProcessors: h.NumberOfProcessors,
		EndTime:            UnixTimeStamp(h.EndTime).UTC(),
		TimerResolution:    h.TimerResolution,
		MaxFileSize:        h.MaximumFileSize,
		LogFileMode:        hexf.NUm32p(h.LogFileMode, false),
		BuffersWritten:     h.BuffersWritten,
		StartBuffers:       h.GetStartBuffers(),
		PointerSize:        h.GetPointerSize(),
		EventsLost:         h.GetEventsLost(),
		CpuSpeedInMHz:      h.GetCpuSpeedInMHz(),
		BootTime:           UnixTimeStamp(h.BootTime).UTC(),
		PerfFreq:           h.PerfFreq,
		StartTime:          UnixTimeStamp(h.StartTime).UTC(),
		ReservedFlags:      h.ReservedFlags,
		BuffersLost:        h.BuffersLost,
		TimeZone: JsonTimeZoneInfo{
			Bias:         h.TimeZone.Bias,
			StandardName: UTF16ToStringETW(h.TimeZone.StandardName[:]),
			StandardDate: JsonTime(h.TimeZone.StandardDate.ToTime()),
			StandardBias: h.TimeZone.StandardBias,
			DaylightName: UTF16ToStringETW(h.TimeZone.DaylightName[:]),
			DaylightDate: JsonTime(h.TimeZone.DaylightDate.ToTime()),
			DaylightBias: h.TimeZone.DaylighBias,
		},
	}, nil
}

// toMarsheableLogFile converts EventTraceLogfile to a JSON-safe struct
func (etl *EventTraceLogfile) ToJSON() (*JsonLogfile, error) {
	if etl == nil {
		return nil, nil
	}

	header, err := etl.LogfileHeader.ToJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to convert header: %w", err)
	}

	safe := &JsonLogfile{
		CurrentTime:   UnixTimeStamp(etl.CurrentTime).UTC(),
		BuffersRead:   etl.BuffersRead,
		ProcessMode:   etl.Union1,
		LogfileHeader: header,
		BufferSize:    etl.BufferSize,
		Filled:        etl.Filled,
		EventsLost:    etl.EventsLost,
		IsKernelTrace: etl.IsKernelTrace,
	}

	if etl.LogFileName != nil {
		safe.LogFileName = UTF16PtrToString(etl.LogFileName)
	}
	if etl.LoggerName != nil {
		safe.LoggerName = UTF16PtrToString(etl.LoggerName)
	}

	return safe, nil
}
