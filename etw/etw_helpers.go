//go:build windows

package etw

import (
	"bytes"
	"encoding/hex" // also slow but not used much here.
	"fmt"

	"math"
	"os"
	"sync"
	"unsafe"

	plog "github.com/phuslu/log"
)

const (
	StructurePropertyName = "Structures"
)

var (
	hostname, _ = os.Hostname()
	isDebug     = os.Getenv("DEBUG") == "1"

	ErrPropertyParsing = fmt.Errorf("error parsing property")
	ErrUnknownProperty = fmt.Errorf("unknown property")
)

// Global Memory Pools
var (
	// We use global pool only for EventRecordHelper and local per goroutine pools for other object.
	helperPool    = sync.Pool{New: func() any { return &EventRecordHelper{} }}
	tdhBufferPool = sync.Pool{New: func() any { s := make([]uint16, 128); return &s }}
)

// localPools holds all the necessary pools for a single goroutine.
type localPools struct {
	//helperPool           sync.Pool
	propertyMapPool      sync.Pool // map[string]*Property // map of properties by name
	arrayPropertyMapPool sync.Pool // map[string]*[]*Property) // map of properties by name to a slice of pointers to Property
	propSlicePool        sync.Pool // *[]*Property
	structArraysMapPool  sync.Pool
	structSingleMapPool  sync.Pool
	selectedPropsPool    sync.Pool
	integerValuesPool    sync.Pool
	epiArrayPool         sync.Pool
	tdhInfoPool          sync.Pool
}

// newLocalPools creates a new set of pools for a goroutine.
// This is to avoid some potential lock contention, we can get as high as 200k events/s
func newLocalPools() *localPools {
	return &localPools{
		//helperPool:           sync.Pool{New: func() any { return &EventRecordHelper{} }},
		propertyMapPool:      sync.Pool{New: func() any { return make(map[string]*Property, 8) }},
		arrayPropertyMapPool: sync.Pool{New: func() any { return make(map[string]*[]*Property) }}, // ? Changed to store pointers
		propSlicePool:        sync.Pool{New: func() any { s := make([]*Property, 0, 8); return &s }},
		structArraysMapPool:  sync.Pool{New: func() any { return make(map[string][]map[string]*Property) }},
		structSingleMapPool:  sync.Pool{New: func() any { s := make([]map[string]*Property, 0, 4); return &s }},
		selectedPropsPool:    sync.Pool{New: func() any { return make(map[string]bool) }},
		integerValuesPool:    sync.Pool{New: func() any { s := make([]uint16, 0, 16); return &s }},
		epiArrayPool:         sync.Pool{New: func() any { s := make([]*EventPropertyInfo, 0, 16); return &s }},
		tdhInfoPool:          sync.Pool{New: func() any { b := make([]byte, 4096); return &b }}, // GetEventInformation() in advapi32_header.go
	}
}

type EventRecordHelper struct {
	EventRec  *EventRecord
	TraceInfo *TraceEventInfo

	// Important: use pointers to slices if using pools to avoid corruption
	// when storing EventRecordHelpers in a global pool.

	Properties      map[string]*Property
	ArrayProperties map[string]*[]*Property           // Changed to store pointers
	StructArrays    map[string][]map[string]*Property // For arrays of structs
	StructSingle    *[]map[string]*Property           // For non-array structs

	Flags struct {
		Skip      bool
		Skippable bool
	}

	// Stored property values for resolving array lengths
	// both are filled when an index is queried
	integerValues *[]uint16
	epiArray      *[]*EventPropertyInfo

	// Buffer that contains the memory for TraceEventInfo.
	// used internally to reuse the memory allocation.
	teiBuffer *[]byte

	// Position of the next byte of event data to be consumed.
	// increments after each call to prepareProperty
	userDataIt uintptr

	// Position of the end of the event data
	// For UserData length check [EventRec.UserDataLength]
	userDataEnd uintptr

	selectedProperties map[string]bool

	// Keep a reference to the pools used to create this helper.
	pools *localPools
}

func (e *EventRecordHelper) remainingUserDataLength() uint16 {
	return uint16(e.userDataEnd - e.userDataIt)
}

func (e *EventRecordHelper) userContext() (c *traceContext) {
	return (*traceContext)(unsafe.Pointer(e.EventRec.UserContext))
}

func (e *EventRecordHelper) addPropError() {
	c := e.userContext()
	if c != nil && c.trace != nil {
		c.trace.ErrorPropsParse.Add(1)
	}
}

// Helper func to log trace event info for debugging
func (e *EventRecordHelper) logTraceInfo(entry *plog.Entry) *plog.Entry {
	if e.TraceInfo != nil {
		entry = entry.
			Str("provider", e.TraceInfo.ProviderName()).
			Str("providerGUID", e.TraceInfo.ProviderGUID.String()).
			Str("event", e.TraceInfo.EventName()).
			Str("eventGUID", e.TraceInfo.EventGUID.String()).
			Str("activityID", e.TraceInfo.ActivityIDName()).
			Str("relatedActivityID", e.TraceInfo.RelatedActivityIDName()).
			Str("keywords", fmt.Sprint(e.TraceInfo.KeywordsName())).
			Str("level", e.TraceInfo.LevelName()).
			Str("task", e.TraceInfo.TaskName()).
			Str("channel", e.TraceInfo.ChannelName()).
			Str("opcode", e.TraceInfo.OpcodeName()).
			Str("event_message", e.TraceInfo.EventMessage()).
			Str("provider_message", e.TraceInfo.ProviderMessage()).
			Uint32("propertyCount", e.TraceInfo.PropertyCount).
			Uint32("topLevelPropertyCount", e.TraceInfo.TopLevelPropertyCount).
			Bool("isMof", e.TraceInfo.IsMof())
	}
	if e.EventRec != nil { // EventHeader
		entry = entry.
			Int("flags", int(e.EventRec.EventHeader.Flags)).
			Str("GUID", e.EventRec.EventHeader.ProviderId.StringU()).
			Int("header_eventID", int(e.EventRec.EventHeader.EventDescriptor.Id)).
			Int("header_version", int(e.EventRec.EventHeader.EventDescriptor.Version)).
			Int("header_opcode", int(e.EventRec.EventHeader.EventDescriptor.Opcode))
	}
	if e.TraceInfo != nil { // EventDescriptor (TraceInfo)
		entry = entry.
			Int("edescriptor_eventID", int(e.TraceInfo.EventID())).
			Int("edescriptor_version", int(e.TraceInfo.EventDescriptor.Version)).
			Int("edescriptor_channel", int(e.TraceInfo.EventDescriptor.Channel)).
			Int("edescriptor_level", int(e.TraceInfo.EventDescriptor.Level)).
			Int("edescriptor_task", int(e.TraceInfo.EventDescriptor.Task)).
			Str("edescriptor_keyword", fmt.Sprintf("0x%X", e.TraceInfo.EventDescriptor.Keyword)).
			Int("edescriptor_opcode", int(e.TraceInfo.EventDescriptor.Opcode))
	}
	return entry
}

// Release EventRecordHelper back to memory pool
// Including all the memory allocations that were made during the processing of the event
// (increases performance)
func (e *EventRecordHelper) release() {
	// Since we have to release the property struct memory by iterating we may as well
	// reset the memory of the maps and slices while doing it
	pools := e.pools // Use the pools associated with this helper instance.

	// Important: Don't store references to slices! that are part of EventRecordHelper
	// This will create subtle data race if we share &internal locations to other pooled structs.

	// 1. Reset/Clear and return to the pool Properties map
	if (e.Properties) != nil {

		for _, p := range e.Properties {
			p.release()
		}
		clear(e.Properties) // Single operation to clear map
		pools.propertyMapPool.Put(e.Properties)
	}

	// 2. Reset/Clear and return ArrayProperties to the pool map[string]*[]*Property
	if (e.ArrayProperties) != nil {
		for _, propSlicePtr := range e.ArrayProperties {
			for _, p := range *propSlicePtr {
				// Release the contents first (*Property)
				p.release()
			}
			// Release the slice *[]
			clear(*propSlicePtr)
			*propSlicePtr = (*propSlicePtr)[:0]
			pools.propSlicePool.Put(propSlicePtr)
		}
		// Release the top-level container map[string]
		clear(e.ArrayProperties)
		pools.arrayPropertyMapPool.Put(e.ArrayProperties)
	}

	// 3a. StructArrays map
	if (e.StructArrays) != nil {
		for _, structs := range e.StructArrays {
			for _, propStruct := range structs {
				for _, p := range propStruct {
					p.release()
				}
				clear(propStruct)
				pools.propertyMapPool.Put(propStruct)
			}
		}
		clear(e.StructArrays)
		pools.structArraysMapPool.Put(e.StructArrays)
	}

	// 3b. SingleStructs slice
	if e.StructSingle != nil {
		for _, propStruct := range *e.StructSingle {
			for _, p := range propStruct {
				p.release()
			}
			clear(propStruct)
			pools.propertyMapPool.Put(propStruct)
		}
		*e.StructSingle = (*e.StructSingle)[:0]
		pools.structSingleMapPool.Put(e.StructSingle)
	}

	// 4. Clear and return selectedProperties
	if e.selectedProperties != nil {
		clear(e.selectedProperties)
		pools.selectedPropsPool.Put(e.selectedProperties)
	}

	// 5. Reset integerValues slice (keep capacity) and return to pool
	if e.integerValues != nil {
		*e.integerValues = (*e.integerValues)[:0]
		pools.integerValuesPool.Put(e.integerValues)
	}

	// 6. Reset epiArray slice (keep capacity) and return to pool
	if e.epiArray != nil {
		// Important: Zero out the pointers in the backing array so that when this
		// slice is reused, it doesn't contain stale pointers from a previous event.
		// This is critical for the `if (*e.epiArray)[i] == nil` check in getEpiAt.
		clear(*e.epiArray)
		*e.epiArray = (*e.epiArray)[:0]
		pools.epiArrayPool.Put(e.epiArray)
	}

	// 7. Release back into the pool the mem allocation for TraceEventInfo
	if e.teiBuffer != nil {
		tdhInfoPool.Put(e.teiBuffer) // use global pool for this one
	}

	// Last. Finally, Reset fields and Release this object memory
	*e = EventRecordHelper{}
	//pools.helperPool.Put(e) // Put back into the goroutine specific pool
	helperPool.Put(e)
}

// Creates a new EventRecordHelper that has the EVENT_RECORD and gets a TRACE_EVENT_INFO for that event.
func newEventRecordHelper(er *EventRecord) (erh *EventRecordHelper, err error) {
	erh = helperPool.Get().(*EventRecordHelper) // Use global pool for this one.
	pools := er.getUserContext().pools
	//erh = pools.helperPool.Get().(*EventRecordHelper)
	erh.pools = pools // Associate the pools with this helper instance.

	erh.EventRec = er
	if erh.TraceInfo, erh.teiBuffer, err = er.GetEventInformation(); err != nil {
		err = fmt.Errorf("GetEventInformation failed : %s", err)
		erh.logTraceInfo(plog.Error()).Msg("GetEventInformation failed")
	}

	return
}

// This memory was already reseted when it was released.
func (e *EventRecordHelper) initialize() {
	pools := e.pools
	e.Properties = pools.propertyMapPool.Get().(map[string]*Property)
	e.ArrayProperties = pools.arrayPropertyMapPool.Get().(map[string]*[]*Property)

	// Structure handling
	e.StructArrays = pools.structArraysMapPool.Get().(map[string][]map[string]*Property)
	e.StructSingle = pools.structSingleMapPool.Get().(*[]map[string]*Property)

	e.selectedProperties = pools.selectedPropsPool.Get().(map[string]bool)

	maxPropCount := int(e.TraceInfo.PropertyCount)
	// Get and resize integer values
	e.integerValues = pools.integerValuesPool.Get().(*[]uint16)
	if cap(*e.integerValues) < maxPropCount {
		*e.integerValues = make([]uint16, maxPropCount)
	} else {
		*e.integerValues = (*e.integerValues)[:maxPropCount]
	}

	// Get and resize epi array
	e.epiArray = pools.epiArrayPool.Get().(*[]*EventPropertyInfo)
	if cap(*e.epiArray) < maxPropCount {
		*e.epiArray = make([]*EventPropertyInfo, maxPropCount)
	} else {
		*e.epiArray = (*e.epiArray)[:maxPropCount]
	}

	// userDataIt iterator will be incremented for each queried property by prop size
	e.userDataIt = e.EventRec.UserData
	e.userDataEnd = e.EventRec.UserData + uintptr(e.EventRec.UserDataLength)
}

// For when there is no trace information available
func (e *EventRecordHelper) setEventMetadataNoTrace(event *Event) {
	if e.EventRec.IsMof() && e.TraceInfo == nil {
		eventDescriptor := e.EventRec.EventHeader.EventDescriptor

		event.System.EventID = e.EventRec.EventID()
		event.System.Version = eventDescriptor.Version

		event.System.Provider.Guid = nullGUID
		event.System.Level.Value = eventDescriptor.Level
		event.System.Opcode.Value = eventDescriptor.Opcode // eventType
		event.System.Keywords.Mask = eventDescriptor.Keyword
		event.System.Task.Value = uint8(eventDescriptor.Task)

		var eventType string
		if c := MofErLookup(e.EventRec); c != nil {
			eventType = c.Name
			// if t, ok := MofClassMapping[e.EventRec.EventHeader.ProviderId.Data1]; ok {
			// 	event.System.EventType = t.Name
		} else {
			eventType = "UnknownClass"
		}

		event.System.EventType = eventType
		event.System.EventGuid = e.EventRec.EventHeader.ProviderId
		event.System.Correlation.ActivityID = nullGUIDStr
		event.System.Correlation.RelatedActivityID = nullGUIDStr

	}
}

func (e *EventRecordHelper) setEventMetadata(event *Event) {
	event.System.Computer = hostname

	// Some Providers don't have a ProcessID or ThreadID (there are set 0xFFFFFFFF)
	// because some events are logged by separate threads
	if e.EventRec.EventHeader.ProcessId == math.MaxUint32 {
		event.System.Execution.ProcessID = 0
	} else {
		event.System.Execution.ProcessID = e.EventRec.EventHeader.ProcessId
	}
	if e.EventRec.EventHeader.ThreadId == math.MaxUint32 {
		event.System.Execution.ThreadID = 0
	} else {
		event.System.Execution.ThreadID = e.EventRec.EventHeader.ThreadId
	}

	event.System.Execution.ProcessorID = uint16(e.EventRec.BufferContext.Processor)

	// NOTE: for private session use e.EventRec.EventHeader.ProcessorTime
	if e.EventRec.EventHeader.Flags&
		(EVENT_HEADER_FLAG_PRIVATE_SESSION|EVENT_HEADER_FLAG_NO_CPUTIME) == 0 {
		event.System.Execution.KernelTime = e.EventRec.EventHeader.GetKernelTime()
		event.System.Execution.UserTime = e.EventRec.EventHeader.GetUserTime()
	} else {
		event.System.Execution.ProcessorTime = e.EventRec.EventHeader.ProcessorTime
	}

	// EVENT_RECORD.EVENT_HEADER.EventDescriptor == TRACE_EVENT_INFO.EventDescriptor for MOF events
	event.System.EventID = e.TraceInfo.EventID()
	event.System.Version = e.TraceInfo.EventDescriptor.Version
	event.System.Channel = e.TraceInfo.ChannelName()

	event.System.Provider.Guid = e.TraceInfo.ProviderGUID
	event.System.Provider.Name = e.TraceInfo.ProviderName()
	event.System.Level.Value = e.TraceInfo.EventDescriptor.Level
	event.System.Level.Name = e.TraceInfo.LevelName()
	event.System.Opcode.Value = e.TraceInfo.EventDescriptor.Opcode
	event.System.Opcode.Name = e.TraceInfo.OpcodeName()
	event.System.Keywords.Mask = e.TraceInfo.EventDescriptor.Keyword
	event.System.Keywords.Name = e.TraceInfo.KeywordsName()
	event.System.Task.Value = uint8(e.TraceInfo.EventDescriptor.Task)
	event.System.Task.Name = e.TraceInfo.TaskName()

	event.System.TimeCreated.SystemTime = e.EventRec.EventHeader.UTCTimeStamp()

	if e.TraceInfo.IsMof() {
		var eventType string
		// e.EventRec.EventHeader.ProviderId is the same as e.TraceInfo.EventGUID
		if c := MofErLookup(e.EventRec); c != nil {
			eventType = fmt.Sprintf("%s/%s", c.Name, e.TraceInfo.OpcodeName())
			// if t, ok := MofClassMapping[e.EventRec.EventHeader.ProviderId.Data1]; ok {
			// 	eventType = fmt.Sprintf("%s/%s", t.Name, e.TraceInfo.OpcodeName())
		} else {
			eventType = fmt.Sprintf("UnknownClass/%s", e.TraceInfo.OpcodeName())
		}

		event.System.EventType = eventType
		event.System.EventGuid = e.TraceInfo.EventGUID
		event.System.Correlation.ActivityID = e.TraceInfo.ActivityIDName()
		event.System.Correlation.RelatedActivityID = e.TraceInfo.RelatedActivityIDName()
	} else {
		event.System.Correlation.ActivityID = e.EventRec.EventHeader.ActivityId.StringU()
		if relatedActivityID := e.EventRec.RelatedActivityID(); relatedActivityID.IsZero() {
			event.System.Correlation.RelatedActivityID = nullGUIDStr
		} else {
			event.System.Correlation.RelatedActivityID = relatedActivityID.StringU()
		}
	}
}

func (e *EventRecordHelper) getPropertySize(i uint32) (size uint32, err error) {
	dataDesc := PropertyDataDescriptor{}
	dataDesc.PropertyName = uint64(e.TraceInfo.PropertyNamePointer(i))
	dataDesc.ArrayIndex = math.MaxUint32
	err = TdhGetPropertySize(e.EventRec, 0, nil, 1, &dataDesc, &size)
	return
}

// Helps when a property length needs to be calculated using a previous property value
// This has to be called on every property to cache the integer values as it goes.
func (e *EventRecordHelper) cacheIntergerValues(i uint32) {
	epi := (*e.epiArray)[i]
	// If this property is a scalar integer, remember the value in case it
	// is needed for a subsequent property's that has the PropertyParamLength flag set.
	// This is a Single Value property, not a struct and it doesn't have a param count
	// Basically: if !isStruct && !hasParamCount && isSingleValue
	if (epi.Flags&(PropertyStruct|PropertyParamCount)) == 0 &&
		epi.Count() == 1 {
		userdr := e.remainingUserDataLength()

		// integerValues is used sequentially, so we can reuse it without reseting
		switch inType := TdhInType(epi.InType()); inType {
		case TDH_INTYPE_INT8,
			TDH_INTYPE_UINT8:
			if (userdr) >= 1 {
				(*e.integerValues)[i] = uint16(*(*uint8)(unsafe.Pointer(e.userDataIt)))
			}
		case TDH_INTYPE_INT16,
			TDH_INTYPE_UINT16:
			if (userdr) >= 2 {
				(*e.integerValues)[i] = *(*uint16)(unsafe.Pointer(e.userDataIt))
			}
		case TDH_INTYPE_INT32,
			TDH_INTYPE_UINT32,
			TDH_INTYPE_HEXINT32:
			if (userdr) >= 4 {
				val := *(*uint32)(unsafe.Pointer(e.userDataIt))
				if val > 0xffff {
					(*e.integerValues)[i] = 0xffff
				} else {
					(*e.integerValues)[i] = uint16(val)
				}
			}
		}
	}
}

// Gets the EventPropertyInfo at index i, caching it for future use.
// also caches the data if it's an integer property if any other property needs it for length.
func (e *EventRecordHelper) getEpiAt(i uint32) *EventPropertyInfo {
	// (epiArray mem is reused, make sure the elements are set to nil before use)
	if (*e.epiArray)[i] == nil {
		(*e.epiArray)[i] = e.TraceInfo.GetEventPropertyInfoAt(i)
		e.cacheIntergerValues(i)
	}
	return (*e.epiArray)[i]
}

// TODO: test performance of this (no bounds checking)
//
//go:nosplit
//go:nocheckptr
func (e *EventRecordHelper) getEpiAt_2(i uint32) *EventPropertyInfo {
	// Direct pointer access to epiArray element without bounds checking
	pEpi := unsafe.Add(unsafe.Pointer(&(*e.epiArray)[0]),
		uintptr(i)*unsafe.Sizeof((*EventPropertyInfo)(nil)))
	if *(**EventPropertyInfo)(pEpi) == nil {
		// Cache miss - get and store EventPropertyInfo
		*(**EventPropertyInfo)(pEpi) = e.TraceInfo.GetEventPropertyInfoAt(i)
		e.cacheIntergerValues(i)
	}
	return *(**EventPropertyInfo)(pEpi)
}

// Returns the length of the property (can be 0) at index i and the actual size in bytes.
func (e *EventRecordHelper) getPropertyLength(i uint32) (propLength uint16, sizeBytes uint32, err error) {
	var epi = e.getEpiAt(i)

	// We recorded the values of all previous integer properties just
	// in case we need to determine the property length or count.
	// integerValues will have our length or count number.
	switch {
	case (epi.Flags & PropertyParamLength) != 0:
		// Length from another property
		propLength = (*e.integerValues)[epi.LengthPropertyIndex()]

	case (epi.Flags & PropertyParamFixedLength) != 0:
		// Fixed length specified in manifest
		propLength = epi.Length()
		if propLength == 0 {
			// Fixed zero length
			return 0, 0, nil
		}

	default:
		// Use length field
		propLength = epi.Length()
	}

	// Fix: Length will be in WCHAR count if TDH_INTYPE_UNICODESTRING
	if (propLength > 0) && (epi.InType() == TDH_INTYPE_UNICODESTRING) {
		sizeBytes = uint32(propLength) * 2
	} else {
		sizeBytes = uint32(propLength)
	}

	//* links:
	// https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-mof-qualifiers#property-qualifiers

	// Improves performance (vs calling TdhGetPropertySize on every variable prop by ~6%)
	// We do this the long way to not abuse cgo calls on every prop.
	// (if go cgo improves in performance this will a 3 liner)
	//
	// Gets byte size for zero length cases (null-terminated or variable)
	if propLength == 0 {
		switch epi.InType() {

		case TDH_INTYPE_BINARY:
			if epi.OutType() == TDH_OUTTYPE_IPV6 &&
				epi.Length() == 0 &&
				(epi.Flags&(PropertyParamLength|PropertyParamFixedLength)) == 0 {
				return 16, 16, nil // special case for incorrectly-defined IPV6 addresses
			}
			if epi.OutType() == TDH_OUTTYPE_HEXBINARY {
				// TdhGetPropertySize returns 0 for these fields.
				// Microsoft-Windows-Kernel-Registry is an example to test.
				// The field is incorrectly encoded or the size is indeed 0.
				// NOTE(will be decoded in string form as "0x")
				return 0, 0, nil
			}
			// Try TdhGetPropertySize for other binary types

		case TDH_INTYPE_UNICODESTRING:
			// For non-null terminated strings, especially at end of event data,
			// use remaining data length as string length
			wchars := unsafe.Slice((*uint16)(unsafe.Pointer(e.userDataIt)),
				e.remainingUserDataLength()/2)
			sizeBytes = 0
			for _, w := range wchars {
				sizeBytes += 2 // include null terminator
				if w == 0 {
					break
				}
			}
			// size may be null included even if not null terminated, doesnt matter.
			// this is the last prop, the iterator will be at the end of the data.
			return 0, sizeBytes, nil

		case TDH_INTYPE_ANSISTRING:
			// Scan until null or end
			chars := unsafe.Slice((*byte)(unsafe.Pointer(e.userDataIt)),
				e.remainingUserDataLength())
			sizeBytes = 0
			for _, c := range chars {
				sizeBytes++ // include null terminator
				if c == 0 {
					break
				}
			}
			// size may be null included even if not null terminated, doesnt matter.
			// this is the last prop, the iterator will be at the end of the data.
			return 0, sizeBytes, nil

		// All counted string/binary types that have 2-byte length prefix
		case TDH_INTYPE_MANIFEST_COUNTEDBINARY,
			TDH_INTYPE_MANIFEST_COUNTEDSTRING,
			TDH_INTYPE_MANIFEST_COUNTEDANSISTRING,
			TDH_INTYPE_COUNTEDSTRING,
			TDH_INTYPE_COUNTEDANSISTRING:
			// Length is little-endian uint16 prefix
			if e.remainingUserDataLength() < 2 {
				break // try tdhGetPropertySize
			}
			sizeBytes = uint32(*(*uint16)(unsafe.Pointer(e.userDataIt))) + 2 // Include length prefix
			return 0, sizeBytes, nil

		case TDH_INTYPE_REVERSEDCOUNTEDSTRING,
			TDH_INTYPE_REVERSEDCOUNTEDANSISTRING:
			// Length is big-endian uint16 prefix
			if e.remainingUserDataLength() < 2 {
				break // try tdhGetPropertySize
			}
			byteLen := *(*uint16)(unsafe.Pointer(e.userDataIt))
			sizeBytes = uint32(Swap16(byteLen)) + 2 // Include length prefix
			return 0, sizeBytes, nil

		case TDH_INTYPE_SID,
			TDH_INTYPE_WBEMSID:
			// SID memory layout:
			// For TDH_INTYPE_SID:
			// +==============================================================+
			// | Offset | Size | Field                  | Description         |
			// |--------|------|------------------------|---------------------|
			// | 0      | 1    | Revision               | SID version (1)     |
			// | 1      | 1    | SubAuthorityCount      | Number of sub-auths |
			// | 2      | 6    | IdentifierAuthority    | Authority ID        |
			// | 8      | 4*N  | SubAuthority[N]        | N sub-authorities   |
			// +==============================================================+
			// Total size = 8 + (4 * SubAuthorityCount) bytes
			//
			// For TDH_INTYPE_WBEMSID:
			// +==============================================================+
			// | Offset | Size   | Field               | Description          |
			// |--------|--------|---------------------|----------------------|
			// | 0      | 4/8    | User ptr            | TOKEN_USER pointer   |
			// | 4/8    | 4/8    | Sid ptr             | SID pointer          |
			// | 8/16   | varies | SID structure       | Same as above        |
			// +==============================================================+
			// Note: First two fields are pointers - size depends on 32/64-bit

			// Minimum SID size is 8 bytes (header + identifier authority, no sub-authorities)
			if e.remainingUserDataLength() < 8 {
				break // try tdhGetPropertySize
			}
			var sidSize uint32
			if epi.InType() == TDH_INTYPE_WBEMSID {
				// For WBEMSID, skip TOKEN_USER structure
				// (contains 2 pointers - size depends on architecture)
				if e.EventRec.PointerSize() == 8 {
					sidSize += 16 // 64-bit: 2 * 8-byte pointers
				} else {
					sidSize += 8 // 32-bit: 2 * 4-byte pointers
				}
			}
			sidPtr := e.userDataIt + uintptr(sidSize) // Skip header
			// Read SubAuthorityCount from SID header
			subAuthCount := *(*uint8)(unsafe.Pointer(sidPtr + 1)) // offset 1 byte for Revision
			sidSize += 8 + (4 * uint32(subAuthCount))             // 8 byte header + 4 bytes per sub-authority
			// Verify we have enough data for the full SID
			if uint32(e.remainingUserDataLength()) <= sidSize {
				break // try tdhGetPropertySize
			}
			return 0, sidSize, nil

		case TDH_INTYPE_HEXDUMP:
			// First 4 bytes contain length
			if e.remainingUserDataLength() < 4 {
				break // try tdhGetPropertySize
			}
			sizeBytes = *(*uint32)(unsafe.Pointer(e.userDataIt))
			return 0, sizeBytes, nil

		default:
			if epi.Flags&PropertyStruct == PropertyStruct {
				// We don't support nested structs yet. ERROR
				break // Use TdhGetPropertySize
			}

			log.Warn().Uint16("intype", epi.InType().V()).Str("outtype",
				epi.OutType().String()).Msg("unexpected length of 0")
		}

		// We already know how to get the size for each intype, but a single mistake could crash the event.
		// Use the tdh functions to advance the pointer when we are not sure of the size in bytes.
		// it shouldn't be called often anyway so it's a small performance loss
		sizeBytes, err = e.getPropertySize(i)
		if err != nil {
			return
		}
	}

	return
}

// Setups a property for parsing, will be parsed later (or not)
func (e *EventRecordHelper) prepareProperty(i uint32) (p *Property, err error) {
	p = getProperty()

	p.evtPropInfo = e.getEpiAt(i)
	p.evtRecordHelper = e
	// the complexity of maintaining a stringCache is larger than the small cost it saves
	p.name = UTF16AtOffsetToString(e.TraceInfo.pointer(), uintptr(p.evtPropInfo.NameOffset))
	p.pValue = e.userDataIt
	p.userDataRemaining = e.remainingUserDataLength()
	p.length, p.sizeBytes, err = e.getPropertyLength(i)
	if err != nil {
		return
	}

	// ! TESTING
	// rawPtr := e.TraceInfo.pointer() + uintptr(p.evtPropInfo.NameOffset)
	// fmt.Printf("Reading property name at 0x%X (offset %d)\n", rawPtr, p.evtPropInfo.NameOffset)
	// fmt.Printf("First 32 bytes: % X\n", unsafe.Slice((*byte)(unsafe.Pointer(rawPtr)), 32))

	// p.length has to be 0 on strings and structures for TdhFormatProperty to work.
	// We use size instead to advance when p.length is 0.
	e.userDataIt += uintptr(p.sizeBytes)

	return
}

// Prepare will partially decode the event, extracting event info for later
// This is a performance optimization to avoid decoding the event values now.
//
// There is a lot of information available in the event even without decoding,
// including timestamp, PID, TID, provider ID, activity ID, and the raw data.
func (e *EventRecordHelper) prepareProperties() (err error) {
	var p *Property

	// TODO: move this to a separate function before TraceInfo is used
	// https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header
	if e.EventRec.IsMof() {
		// If there aren't any event property info structs, use the UserData directly.
		// NOTE: Does this flag mean that TraceInfo will be null too?
		if (e.EventRec.EventHeader.Flags & EVENT_HEADER_FLAG_STRING_ONLY) != 0 {
			str := (*uint16)(unsafe.Pointer(e.EventRec.UserData))
			value := UTF16ToStringETW(
				unsafe.Slice(str, e.EventRec.UserDataLength/2))
			if e.EventRec.UserDataLength != 0 {
				e.SetProperty("String", value)
			}
			return
		}
	}
	// if (e.EventRec.EventHeader.Flags & EVENT_HEADER_FLAG_TRACE_MESSAGE) != 0 {
	// }
	// if (e.EventRec.EventHeader.Flags & EVENT_HEADER_FLAG_CLASSIC_HEADER) != 0 {
	//	// Kernel events
	// }

	for i := uint32(0); i < e.TraceInfo.TopLevelPropertyCount; i++ {
		epi := e.getEpiAt(i)
		if epi == nil {
			e.addPropError()
			e.logTraceInfo(log.Error()).
				Uint32("index", i).
				Uint32("topLevelPropertyCount", e.TraceInfo.TopLevelPropertyCount).
				Msg("prepareProperties: getEpiAt returned nil, skipping property")
			// This is not a fatal error, we can continue processing the event.
			continue
		}

		// Number of elements in the array of EventPropertyInfo.
		var arrayCount uint16
		if (epi.Flags & PropertyParamCount) != 0 {
			// Look up the value of a previous property
			arrayCount = (*e.integerValues)[epi.CountPropertyIndex()]
		} else {
			arrayCount = epi.Count()
		}

		// Note that PropertyParamFixedCount is a new flag and is ignored
		// by many decoders. Without the PropertyParamFixedCount flag,
		// decoders will assume that a property is an array if it has
		// either a count parameter or a fixed count other than 1. The
		// PropertyParamFixedCount flag allows for fixed-count arrays with
		// one element to be propertly decoded as arrays.
		isArray := arrayCount != 1 ||
			(epi.Flags&(PropertyParamCount|PropertyParamFixedCount)) != 0

		var array *[]*Property
		var arrayName string
		var mofString []uint16

		if isArray {
			arrayName = UTF16AtOffsetToString(e.TraceInfo.pointer(), uintptr(epi.NameOffset))
			array = e.pools.propSlicePool.Get().(*[]*Property)
			if cap(*array) < int(arrayCount) {
				*array = make([]*Property, 0, arrayCount)
			}
		}

		// Treat non-array properties as arrays with one element.
		for arrayIndex := uint16(0); arrayIndex < arrayCount; arrayIndex++ {

			// If this property is a struct, process the child properties
			// TODO(tekert): save this in a tree structure?
			if epi.Flags&PropertyStruct != 0 {
				//LogTrace("Processing struct property", "index", arrayIndex)
				propStruct := e.pools.propertyMapPool.Get().(map[string]*Property)

				startIndex := epi.StructStartIndex()
				lastMember := startIndex + epi.NumOfStructMembers()

				for j := startIndex; j < lastMember; j++ {
					if p, err = e.prepareProperty(uint32(j)); err != nil {
						e.addPropError()
						return
					}
					propStruct[p.name] = p
				}
				// Add to appropriate collection
				if isArray {
					// Part of an array - add to StructArrays
					e.StructArrays[arrayName] = append(e.StructArrays[arrayName], propStruct)
				} else {
					// Single struct - add to SingleStructs
					*e.StructSingle = append(*e.StructSingle, propStruct)
				}
				continue
			}

			// If is a simple array of props (not structs)
			if isArray && (epi.Flags&PropertyStruct == 0) {
				// if this is a MOF event, we don't need to parse the properties of the array
				// this will be a array of wchars, Kernel events EVENT_HEADER_FLAG_CLASSIC_HEADER
				if e.TraceInfo.IsMof() {
					if e.EventRec.EventHeader.Flags&EVENT_HEADER_FLAG_CLASSIC_HEADER != 0 {
						if epi.InType() == TDH_INTYPE_UNICODECHAR {
							// C++ Definition example: wchar_t ThreadName[1]; (Variadic arrays)
							// arrayCount is usualy a cap in this case. Fixed 256 byte array usually.
							mofString = unsafe.Slice((*uint16)(unsafe.Pointer(e.userDataIt)), arrayCount)
							value := UTF16ToStringETW(mofString)
							e.SetProperty(arrayName, value)

							e.userDataIt += (uintptr(arrayCount) * 2) // advance pointer
							break                                     // Array parsed.. next property
						}
					}
				} else {
					// If this is not an array of structs, we can parse the properties of the array
					if p, err = e.prepareProperty(i); err != nil {
						e.addPropError()
						if isArray {
							e.pools.propSlicePool.Put(array)
						}
						return
					}
					*array = append(*array, p)
					continue
				}
			}

			// Single value that is not a struct or array.
			if arrayCount == 1 && !isArray {
				if p, err = e.prepareProperty(i); err != nil {
					e.addPropError()
					return
				}
				e.Properties[p.name] = p
			}
		}

		if isArray {
			if len(*array) > 0 {
				e.ArrayProperties[arrayName] = array
			} else {
				// Return the unused slice to the pool.
				e.pools.propSlicePool.Put(array)
			}
		}
	}

	// if the last property did not reach the end of UserData, warning.
	if e.userDataIt < e.userDataEnd {
		remainingBytes := uint32(e.userDataEnd - e.userDataIt)
		remainingData := unsafe.Slice((*byte)(unsafe.Pointer(e.userDataIt)), remainingBytes)

		// Probably this is because TraceEventInfo used an older Thread_V2_TypeGroup1
		// instead of a Thread_V3_TypeGroup1 MOF class to decode it.
		// Try to parse the remaining data as a MOF property.
		// TODO: remvoe this?
		if e.TraceInfo.IsMof() {
			if err2 := e.prepareMofProperty(remainingData, remainingBytes); err2 == nil {
				return nil // data parsed, return.
			}
		}

		e.addPropError()
		e.logTraceInfo(log.Warn()).
			Uint32("remaining", remainingBytes).
			Int("total", int(e.EventRec.UserDataLength)).
			Str("remainingHex", hex.EncodeToString(remainingData)). // Convert data to hex string and report.
			Msg("UserData not fully parsed")
	}

	return
}

// This is a common pattern with kernel ETW events where newer fields are added
// but backward compatibility needs to be maintained, so we must check if the
// data is a new field.
// TODO(tekert): use the new kernel mof generated classes to decode this.
func (e *EventRecordHelper) prepareMofProperty(remainingData []byte, remaining uint32) (last error) {
	// Check if all bytes are padding (zeros)
	if bytes.IndexFunc(remainingData, func(r rune) bool {
		return r != 0
	}) == -1 {
		return nil
	}

	eventID := e.TraceInfo.EventID()
	//eventType := e.TraceInfo.EventDescriptor.Opcode

	// Thread_V3_TypeGroup1 new ThreadName not included in TraceEventInfo propierties on Windows 10.
	if (eventID == 5358 || // Thread/DCStart
		eventID == 5357 || // Thread/End
		eventID == 5359) && // Thread/DCEnd
		remaining > 2 {
		threadName := UTF16BytesToString(remainingData)
		e.SetProperty("ThreadName", threadName)
		return nil
	}

	// Handle SystemConfig PnP events with device names
	if eventID == 1807 && // SystemConfig/PnP
		remaining > 2 {
		deviceName := UTF16BytesToString(remainingData)
		e.SetProperty("DeviceName", deviceName)
		return nil
	}

	return fmt.Errorf("unhandled MOF event %d", eventID)
}

// Get the MOF class GUID
func (e *EventRecordHelper) mofClassGuid() *GUID {
	return &e.EventRec.EventHeader.ProviderId
}

// Get the MOF event type
func (e *EventRecordHelper) mofEventType() uint8 {
	return e.EventRec.EventHeader.EventDescriptor.Opcode
}

// Get the MOF class version
func (e *EventRecordHelper) mofClassVersion() uint8 {
	return e.EventRec.EventHeader.EventDescriptor.Version
}

// func (e *EventRecordHelper) prepareMofEvent() error {

// }

// func parseMofProperty(data []byte, prop MofPropertyDef) (interface{}, int, error) {

// }

func (e *EventRecordHelper) buildEvent() (event *Event, err error) {
	event = NewEvent()

	event.Flags.Skippable = e.Flags.Skippable

	if err = e.parseAndSetAllProperties(event); err != nil {
		return
	}

	e.setEventMetadata(event)

	return
}

func (e *EventRecordHelper) parseAndSetProperty(name string, out *Event) (err error) {

	eventData := out.EventData

	// it is a user data property
	if (e.TraceInfo.Flags & TEMPLATE_USER_DATA) == TEMPLATE_USER_DATA {
		eventData = out.UserData
	}

	if p, ok := e.Properties[name]; ok {
		if eventData[p.name], err = p.FormatToString(); err != nil {
			return fmt.Errorf("%w %s: %s", ErrPropertyParsing, name, err)
		}
	}

	// parsing array
	if propSlicePtr, ok := e.ArrayProperties[name]; ok {
		values := make([]string, 0, len(*propSlicePtr))

		// iterate over the properties
		for _, p := range *propSlicePtr {
			var v string
			if v, err = p.FormatToString(); err != nil {
				return fmt.Errorf("%w array %s: %s", ErrPropertyParsing, name, err)
			}

			values = append(values, v)
		}

		eventData[name] = values
	}

	// Structure arrays
	if structs, ok := e.StructArrays[name]; ok {
		if structArray, err := e.formatStructs(structs, name); err != nil {
			return err
		} else {
			eventData[name] = structArray
		}
	}

	// Single structs - only check if requesting StructurePropertyName
	if name == StructurePropertyName && len(*e.StructSingle) > 0 {
		if structs, err := e.formatStructs(*e.StructSingle, StructurePropertyName); err != nil {
			return err
		} else {
			eventData[StructurePropertyName] = structs
		}
	}

	return
}

func (e *EventRecordHelper) shouldParse(name string) bool {
	if len(e.selectedProperties) == 0 {
		return true
	}
	_, ok := e.selectedProperties[name]
	return ok
}

// this a bit inneficient, but it's not a big deal, we ussually want a few properties not all.
func (e *EventRecordHelper) parseAndSetAllProperties(out *Event) (last error) {
	var err error

	eventData := out.EventData

	// it is a user data property
	if (e.TraceInfo.Flags & TEMPLATE_USER_DATA) == TEMPLATE_USER_DATA {
		eventData = out.UserData
	}

	// Properties
	for _, p := range e.Properties {
		if !e.shouldParse(p.name) {
			continue
		}
		if _, err := p.FormatToString(); err != nil {
			last = fmt.Errorf("%w %s: %s", ErrPropertyParsing, p.name, err)
		} else {
			eventData[p.name] = p.value
		}
	}

	// Arrays
	for pname, propsPtr := range e.ArrayProperties {
		if !e.shouldParse(pname) {
			continue
		}

		props := *propsPtr
		values := make([]string, 0, len(props))

		// iterate over the properties
		for _, p := range props {
			var v string
			if v, err = p.FormatToString(); err != nil {
				last = fmt.Errorf("%w array %s: %s", ErrPropertyParsing, pname, err)
			}

			values = append(values, v)
		}

		eventData[pname] = values
	}

	// Handle struct arrays
	for name, structs := range e.StructArrays {
		if !e.shouldParse(name) {
			continue
		}
		if structArray, err := e.formatStructs(structs, name); err != nil {
			last = err
		} else {
			eventData[name] = structArray
		}
	}

	// Handle single structs
	if len(*e.StructSingle) > 0 && e.shouldParse(StructurePropertyName) {
		if structs, err := e.formatStructs(*e.StructSingle, StructurePropertyName); err != nil {
			last = err
		} else {
			eventData[StructurePropertyName] = structs
		}
	}

	return
}

func (e *EventRecordHelper) formatStructs(structs []map[string]*Property, name string) ([]map[string]string, error) {
	result := make([]map[string]string, 0, len(structs)) // TODO(tekert): use pools?
	var err error

	for _, propStruct := range structs {
		s := make(map[string]string)
		for field, prop := range propStruct {
			if s[field], err = prop.FormatToString(); err != nil {
				return nil, fmt.Errorf("%w struct %s.%s: %s", ErrPropertyParsing, name, field, err)
			}
		}
		result = append(result, s)
	}
	return result, nil
}

/** Public methods **/

// SelectFields selects the properties that will be parsed and populated
// in the parsed ETW event. If this method is not called, all properties will
// be parsed and put in the event.
func (e *EventRecordHelper) SelectFields(names ...string) {
	for _, n := range names {
		e.selectedProperties[n] = true
	}
}

func (e *EventRecordHelper) ProviderGUID() GUID {
	return e.TraceInfo.ProviderGUID
}

func (e *EventRecordHelper) Provider() string {
	return e.TraceInfo.ProviderName()
}

func (e *EventRecordHelper) Channel() string {
	return e.TraceInfo.ChannelName()
}

func (e *EventRecordHelper) EventID() uint16 {
	return e.TraceInfo.EventID()
}

func (e *EventRecordHelper) GetPropertyString(name string) (s string, err error) {

	if p, ok := e.Properties[name]; ok {
		return p.FormatToString()
	}

	return "", fmt.Errorf("%w %s", ErrUnknownProperty, name)
}

func (e *EventRecordHelper) GetPropertyInt(name string) (i int64, err error) {
	if p, ok := e.Properties[name]; ok {
		return p.GetInt()
	}
	return 0, fmt.Errorf("%w %s", ErrUnknownProperty, name)
}

func (e *EventRecordHelper) GetPropertyUint(name string) (uint64, error) {
	if p, ok := e.Properties[name]; ok {
		return p.GetUInt()
	}
	return 0, fmt.Errorf("%w %s", ErrUnknownProperty, name)
}

func (e *EventRecordHelper) GetPropertyFloat(name string) (float64, error) {
	if p, ok := e.Properties[name]; ok {
		return p.GetFloat()
	}
	return 0, fmt.Errorf("%w %s", ErrUnknownProperty, name)
}

// SetProperty sets or updates a property value in the Properties map.
//
// This is used to set a property value manually. This is useful when
// you want to add a property that is not present in the event record.
func (e *EventRecordHelper) SetProperty(name, value string) *Property {
	if p, ok := e.Properties[name]; ok {
		p.value = value
		return p
	}

	p := getProperty()
	p.name = name
	p.value = value
	e.Properties[name] = p
	return p
}

func (e *EventRecordHelper) ParseProperties(names ...string) (err error) {
	for _, name := range names {
		if err = e.ParseProperty(name); err != nil {
			return
		}
	}

	return
}

func (e *EventRecordHelper) ParseProperty(name string) (err error) {
	if p, ok := e.Properties[name]; ok {
		if _, err = p.FormatToString(); err != nil {
			return fmt.Errorf("%w %s: %s", ErrPropertyParsing, name, err)
		}
	}

	// parsing array
	if propSlicePtr, ok := e.ArrayProperties[name]; ok {
		// iterate over the properties
		for _, p := range *propSlicePtr {
			if _, err = p.FormatToString(); err != nil {
				return fmt.Errorf("%w array %s: %s", ErrPropertyParsing, name, err)
			}
		}
	}

	// Structure arrays
	if structs, ok := e.StructArrays[name]; ok {
		for _, propStruct := range structs {
			for field, prop := range propStruct {
				if _, err = prop.FormatToString(); err != nil {
					return fmt.Errorf("%w struct %s.%s: %s", ErrPropertyParsing, name, field, err)
				}
			}
		}
	}

	// Single structs - only check if requesting StructurePropertyName
	if name == StructurePropertyName && len(*e.StructSingle) > 0 {
		for _, propStruct := range *e.StructSingle {
			for field, prop := range propStruct {
				if _, err = prop.FormatToString(); err != nil {
					return fmt.Errorf("%w struct %s.%s: %s", ErrPropertyParsing, StructurePropertyName, field, err)
				}
			}
		}
	}

	return
}

// Skippable marks the event as "droppable" when the consumer channel is full.
// Events marked as skippable will not block the ETW callback when trying to send
// to a full Event channel. Instead, they will be counted in [Consumer.Skipped] and dropped.
// This is useful for high-volume, low-priority events where losing some events
// is preferable to blocking the ETW callback.
func (e *EventRecordHelper) Skippable() {
	e.Flags.Skippable = true
}

// Skip marks the event to be completely ignored during processing.
// When an event is marked with Skip, it will not be parsed or sent to
// the consumer channel at all. The event processing stops immediately
// after the current callback returns.
// This is useful when you want to filter out events early in the
// processing pipeline before any parsing overhead.
func (e *EventRecordHelper) Skip() {
	e.Flags.Skip = true
}
