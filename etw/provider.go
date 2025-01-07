//go:build windows
// +build windows

package etw

import (
	"fmt"
	"strconv"
	"strings"
	"unsafe"
)

var (
	providers ProviderMap

	DefaultProvider = Provider{EnableLevel: 0xff}

	// Error returned when a provider is not found on the system
	ErrUnkownProvider = fmt.Errorf("unknown provider")
)

type ProviderMap map[string]*Provider

type Provider struct {
	GUID GUID
	Name string

	// The logging level specified. Standard logging levels are:
	// 0 — Log Always; 1 — Critical; 2 — Error; 3 — Warning; 4 — Informational; 5 — Verbose.
	// Custom logging levels can also be defined, but levels 6–15 are reserved.
	// More than one logging level can be captured by ORing respective levels;
	// supplying 255 (0xFF) is the standard method of capturing all supported logging levels.
	// Note that if you set the Level to LogAlways, it ensures that all error events will always be written.
	EnableLevel uint8

	// 64-bit bitmask of keywords that determine the categories of events that you want the provider to write.
	// The provider typically writes an event if the event's keyword bits match any of the bits set in this
	// value or if the event has no keyword bits set, in addition to meeting the Level and MatchAllKeyword criteria.
	//
	// When used with modern (manifest-based or TraceLogging) providers, a MatchAnyKeyword value of 0 is treated
	// the same as a MatchAnyKeyword value of 0xFFFFFFFFFFFFFFFF, i.e. it enables all event keywords.
	// However, this behavior does not apply to legacy (MOF or TMF-based WPP) providers.
	// To enable all event keywords from a legacy provider, set MatchAnyKeyword to 0xFFFFFFFF.
	// To enable all event keywords from both legacy and modern providers, set MatchAnyKeyword to 0xFFFFFFFFFFFFFFFF.
	//
	// Filtering at kernel level is inherently faster than user mode filtering (following the parsing process).
	MatchAnyKeyword uint64

	// 64-bit bitmask of keywords that restricts the events that you want the provider to write.
	// The provider typically writes an event if the event's keyword bits match all of the bits
	// set in this value or if the event has no keyword bits set, in addition to meeting the Level
	//and MatchAnyKeyword criteria.
	//
	// This value is frequently set to 0.
	//
	// Note that this mask is not used if Keywords(Any) is set to zero.
	MatchAllKeyword uint64

	// This is used only for filtering Event IDs for now.
	//
	// For more info read:
	// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2#remarks
	// https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-enable_trace_parameters EnableFilterDesc
	// https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_filter_descriptor EVENT_FILTER_TYPE_EVENT_ID
	//
	// (This kind of filtering is only effective in reducing trace data volume and is not as effective
	// for reducing trace CPU overhead)
	Filter []uint16
}

// IsZero returns true if the provider is empty
func (p *Provider) IsZero() bool {
	return p.GUID.IsZero()
}

func (p *Provider) eventIDFilterDescriptor() (d EventFilterDescriptor) {

	efeid := AllocEventFilterEventID(p.Filter)
	// Enable this event ID (0x0 disables events with this id)
	efeid.FilterIn = 0x1

	d = EventFilterDescriptor{
		Ptr:  uint64(uintptr(unsafe.Pointer(efeid))),
		Size: uint32(efeid.Size()),
		Type: EVENT_FILTER_TYPE_EVENT_ID,
	}

	return
}

func (p *Provider) BuildFilterDesc() (fd []EventFilterDescriptor) {

	fd = append(fd, p.eventIDFilterDescriptor())

	return
}

// MustParseProvider parses a provider string or panic
func MustParseProvider(s string) (p Provider) {
	var err error
	if p, err = ParseProvider(s); err != nil {
		panic(err)
	}
	return
}

// IsKnownProvider returns true if the provider is known
func IsKnownProvider(p string) bool {
	prov := ResolveProvider(p)
	return !prov.IsZero()
}

// ParseProvider parses a string and returns a provider.
// The returned provider is initialized from DefaultProvider.
// Format (Name|GUID) string:EnableLevel uint8:Event IDs comma sep string:MatchAnyKeyword uint16:MatchAllKeyword uint16
//
// Example: Microsoft-Windows-Kernel-File:0xff:13,14:0x80
//
// (0xff here means any Level, 13 and 14 are the event IDs and 0x80 is the MatchAnyKeyword)
//
// You can check the keywords and level using this command in console: logman query providers "<provider_name>"
//
// For events ID the best way is to check the manifest in your system. Use https://github.com/zodiacon/EtwExplorer
//
// More info at: https://learn.microsoft.com/en-us/windows/win32/wes/defining-keywords-used-to-classify-types-of-events
func ParseProvider(s string) (p Provider, err error) {
	var u uint64

	split := strings.Split(s, ":")
	for i := 0; i < len(split); i++ {
		chunk := split[i]
		switch i {
		case 0:
			p = ResolveProvider(chunk)
			if p.IsZero() {
				err = fmt.Errorf("%w %s", ErrUnkownProvider, chunk)
				return
			}
		case 1:
			if chunk == "" {
				break
			}
			// parsing EnableLevel
			if u, err = strconv.ParseUint(chunk, 0, 8); err != nil {
				err = fmt.Errorf("failed to parse EnableLevel: %w", err)
				return
			} else {
				p.EnableLevel = uint8(u)
			}
		case 2:
			if chunk == "" {
				break
			}
			// parsing event ids
			for _, eid := range strings.Split(chunk, ",") {
				if u, err = strconv.ParseUint(eid, 0, 16); err != nil {
					err = fmt.Errorf("failed to parse EventID: %w", err)
					return
				} else {
					p.Filter = append(p.Filter, uint16(u))
				}
			}
		case 3:
			if chunk == "" {
				break
			}

			// parsing MatchAnyKeyword
			if u, err = strconv.ParseUint(chunk, 0, 64); err != nil {
				err = fmt.Errorf("failed to parse MatchAnyKeyword: %w", err)
				return
			} else {
				p.MatchAnyKeyword = u
			}
		case 4:
			if chunk == "" {
				break
			}

			// parsing MatchAllKeyword
			if u, err = strconv.ParseUint(chunk, 0, 64); err != nil {
				err = fmt.Errorf("failed to parse MatchAllKeyword: %w", err)
				return
			} else {
				p.MatchAllKeyword = u
			}
		default:
			return
		}
	}
	return
}

// EnumerateProviders returns a ProviderMap containing available providers,
// keys are both provider's GUIDs and provider's names
func EnumerateProviders() (m ProviderMap) {
	var buf *ProviderEnumerationInfo
	size := uint32(1)
	for {
		tmp := make([]byte, size)
		buf = (*ProviderEnumerationInfo)(unsafe.Pointer(&tmp[0]))
		if err := TdhEnumerateProviders(buf, &size); err != ERROR_INSUFFICIENT_BUFFER {
			break
		}
	}
	m = make(ProviderMap)
	startProvEnumInfo := uintptr(unsafe.Pointer(buf))
	it := uintptr(unsafe.Pointer(&buf.TraceProviderInfoArray[0]))
	for i := uintptr(0); i < uintptr(buf.NumberOfProviders); i++ {
		ptpi := (*TraceProviderInfo)(unsafe.Pointer(it + i*unsafe.Sizeof(buf.TraceProviderInfoArray[0])))
		guidString := ptpi.ProviderGuid.String()
		name := UTF16AtOffsetToString(startProvEnumInfo, uintptr(ptpi.ProviderNameOffset))
		// We use a default provider here
		p := DefaultProvider
		p.GUID = ptpi.ProviderGuid
		p.Name = name
		m[name] = &p
		m[guidString] = &p
	}
	return
}

// ResolveProvider return a Provider structure given a GUID or
// a provider name as input
func ResolveProvider(s string) (p Provider) {

	if providers == nil {
		providers = EnumerateProviders()
	}

	if g, err := ParseGUID(s); err == nil {
		s = g.String()
	}

	if prov, ok := providers[s]; ok {
		// search provider by name
		return *prov
	}

	return
}
