//go:build windows
// +build windows

package etw

import (
	"fmt"
	"log/slog" // use GOLANG_LOG=debug to see debug messages
	"math"
	"os"
	"strconv"
	"sync"
	"syscall"
	"unsafe"
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

// Memory Pools
var (
	// Reuse memory for TraceEventInfo when calling GetEventInformation()
	// Can be reused for every new event record.
	eventRecordHelperPool = sync.Pool{
		New: func() interface{} {
			return &EventRecordHelper{}
		},
	}

	propertyMapPool = sync.Pool{
		New: func() interface{} {
			return make(map[string]*Property)
		},
	}
	arrayPropertyMapPool = sync.Pool{
		New: func() interface{} {
			return make(map[string][]*Property)
		},
	}
	structuresSlicePool = sync.Pool{
		New: func() interface{} {
			s := make([]map[string]*Property, 0)
			return &s // Return pointer
		},
	}

	selectedPropertiesPool = sync.Pool{
		New: func() interface{} {
			return make(map[string]bool)
		},
	}

	integerValuesPool = sync.Pool{
		New: func() interface{} {
			s := make([]uint16, 0)
			return &s
		},
	}

	epiArrayPool = sync.Pool{
		New: func() interface{} {
			s := make([]*EventPropertyInfo, 0)
			return &s
		},
	}

	tdhBufferPool = sync.Pool{
		New: func() interface{} {
			s := make([]uint16, 128)
			return &s
		},
	}
)

func maxu32(a, b uint32) uint32 {
	if a < b {
		return b
	}
	return a
}

type EventRecordHelper struct {
	EventRec  *EventRecord
	TraceInfo *TraceEventInfo

	Properties      map[string]*Property
	ArrayProperties map[string][]*Property
	Structures      []map[string]*Property

	Flags struct {
		Skip      bool
		Skippable bool
	}

	// Stored property values for resolving array lengths
	// both are filled when an index is queried
	integerValues []uint16
	epiArray      []*EventPropertyInfo

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
}

func (e *EventRecordHelper) remainingUserDataLength() uint16 {
	return uint16(e.userDataEnd - e.userDataIt)
}

func (e *EventRecordHelper) userContext() (c *traceContext) {
	return (*traceContext)(unsafe.Pointer(e.EventRec.UserContext))
}

func (e *EventRecordHelper) addPropError() {
	c := e.userContext()
	if c != nil && c.consumer != nil {
		c.trace.ErrorPropsParse++
	}
}

// Release EventRecordHelper back to memory pool
// Including all the memory allocations that were made during the processing of the event
// (increases performance)
func (e *EventRecordHelper) release() {
	// Since we have to release the property struct memory by iterating we may as well
	// reset the memory of the maps and slices while doing it

	// 1. Reset/Clear and return to the pool Properties map
	if (e.Properties) != nil {
		for k, p := range e.Properties {
			p.release()
			delete(e.Properties, k)
		}
		propertyMapPool.Put(e.Properties)
	}

	// 2. Reset/Clear and return ArrayProperties to the pool
	if (e.ArrayProperties) != nil {
		for k, p := range e.ArrayProperties {
			for _, p := range p {
				p.release()
			}
			delete(e.ArrayProperties, k)
		}
		arrayPropertyMapPool.Put(e.ArrayProperties)
	}

	// 3. Reset/Clear and return Structures to the pool
	if (e.Structures) != nil {
		for i := range e.Structures {
			for k, p := range e.Structures[i] {
				p.release()
				delete(e.Structures[i], k)
			}
			// Return inner map to pool
			propertyMapPool.Put(e.Structures[i])
		}
		e.Structures = e.Structures[:0] // Reset length, keep capacity
		structuresSlicePool.Put(&e.Structures)
	}

	// 4. Clear and return selectedProperties
	if (e.selectedProperties) != nil {
		clear(e.selectedProperties)
		selectedPropertiesPool.Put(e.selectedProperties)
	}

	// 5. Reset integerValues slice (keep capacity) and return to pool
	if (e.integerValues) != nil {
		e.integerValues = e.integerValues[:0]
		integerValuesPool.Put(&e.integerValues)
	}

	// 6. Reset epiArray slice (keep capacity) and return to pool
	if (e.epiArray) != nil {
		clear(e.epiArray) // important
		e.epiArray = e.epiArray[:0]
		epiArrayPool.Put(&e.epiArray)
	}

	// 7. Release back into the pool the mem allocation for TraceEventInfo
	if e.teiBuffer != nil {
		tdhInfoPool.Put(e.teiBuffer)
	}

	// Last. Finally, Reset fields and Release this object memory
	*e = EventRecordHelper{}
	eventRecordHelperPool.Put(e)
}

// Creates a new EventRecordHelper that has the EVENT_RECORD and gets a TRACE_EVENT_INFO for that event.
func newEventRecordHelper(er *EventRecord) (erh *EventRecordHelper, err error) {
	erh = eventRecordHelperPool.Get().(*EventRecordHelper)

	erh.EventRec = er

	// if (er.EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) != 0 {
	// 	erh.Flags.Skip = true //! TESTING
	// 	return erh, fmt.Errorf("skip classic header event")
	// }

	if erh.TraceInfo, erh.teiBuffer, err = er.GetEventInformation(); err != nil {
		err = fmt.Errorf("GetEventInformation failed : %s", err)
	}

	return
}

// [OLD] Creates a new EventRecordHelper that has the EVENT_RECORD and gets a TRACE_EVENT_INFO for that event.
func newEventRecordHelper_old(er *EventRecord) (erh *EventRecordHelper, err error) {
	erh = &EventRecordHelper{}
	erh.EventRec = er

	if erh.TraceInfo, err = er.GetEventInformation_old(); err != nil {
		err = fmt.Errorf("TdhGetEventInformation failed with 0x : %s", err)
	}

	return
}

func (e *EventRecordHelper) initialize() {
	// This memory was already reseted when it was released.
	e.Properties = propertyMapPool.Get().(map[string]*Property)
	e.ArrayProperties = arrayPropertyMapPool.Get().(map[string][]*Property)
	e.Structures = *(structuresSlicePool.Get().(*[]map[string]*Property))

	e.selectedProperties = selectedPropertiesPool.Get().(map[string]bool)

	// Get and resize integer values
	e.integerValues = *integerValuesPool.Get().(*[]uint16)
	if cap(e.integerValues) < int(e.TraceInfo.PropertyCount) {
		e.integerValues = make([]uint16, e.TraceInfo.PropertyCount)
	} else {
		e.integerValues = e.integerValues[0:e.TraceInfo.PropertyCount]
	}

	// Get and resize epi array
	e.epiArray = *epiArrayPool.Get().(*[]*EventPropertyInfo)
	if cap(e.epiArray) < int(e.TraceInfo.PropertyCount) {
		e.epiArray = make([]*EventPropertyInfo, e.TraceInfo.PropertyCount)
	} else {
		e.epiArray = e.epiArray[0:e.TraceInfo.PropertyCount]
	}

	// userDataIt iterator will be incremented for each queried property by prop size
	e.userDataIt = e.EventRec.UserData
	e.userDataEnd = e.EventRec.UserData + uintptr(e.EventRec.UserDataLength)
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

	event.System.EventID = e.TraceInfo.EventID()
	event.System.Version = e.TraceInfo.EventVersion()
	event.System.Channel = e.TraceInfo.ChannelName()

	event.System.Provider.Guid = e.TraceInfo.ProviderGUID.String()
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
		if t, ok := MofClassMapping[e.TraceInfo.EventGUID.Data1]; ok {
			eventType = fmt.Sprintf("%s/%s", t.Name, event.System.Opcode.Name)
		} else {
			eventType = fmt.Sprintf("UnknownClass/%s", event.System.Opcode.Name)
		}
		event.System.EventType = eventType
		event.System.EventGuid = e.TraceInfo.EventGUID.String()
		event.System.Correlation.ActivityID = e.TraceInfo.ActivityIDName()
		event.System.Correlation.RelatedActivityID = e.TraceInfo.RelatedActivityIDName()
	} else {
		event.System.Correlation.ActivityID = e.EventRec.EventHeader.ActivityId.String()
		if relatedActivityID := e.EventRec.RelatedActivityID(); relatedActivityID.IsZero() {
			event.System.Correlation.RelatedActivityID = nullGUIDStr
		} else {
			event.System.Correlation.RelatedActivityID = relatedActivityID.String()
		}
	}
}

// https://learn.microsoft.com/en-us/windows/win32/etw/using-tdhformatproperty-to-consume-event-data
//
// GetPropertyLength returns an associated length of the @j-th property of TraceInfo.
// If the length is available, retrieve it here. In some cases, the length is 0.
// This can signify that we are dealing with a variable length field such as a structure
// or a string.
func (e *EventRecordHelper) getPropertyLength_old(i uint32) (uint16, error) {
	// If the property is a buffer, the property can define the buffer size or it can
	// point to another property whose value defines the buffer size. The PropertyParamLength
	// flag tells you where the buffer size is defined.
	epi := e.TraceInfo.GetEventPropertyInfoAt(i)
	if (epi.Flags & PropertyParamLength) == PropertyParamLength {
		length := uint16(0)
		j := uint32(epi.LengthPropertyIndex())
		dataDescriptor := PropertyDataDescriptor{}
		// Get pointer to property name
		dataDescriptor.PropertyName = uint64(e.TraceInfo.pointer()) + uint64(e.TraceInfo.GetEventPropertyInfoAt(j).NameOffset)
		dataDescriptor.ArrayIndex = math.MaxUint32
		// Get length from property
		//* TODO(tekert): lower performance, read: https://learn.microsoft.com/en-us/windows/win32/etw/using-tdhgetproperty-to-consume-event-data
		propertySize := uint32(0)
		if err := TdhGetPropertySize(e.EventRec, 0, nil, 1, &dataDescriptor, &propertySize); err != nil {
			return 0, fmt.Errorf("failed to get property size: %s", err)
		}
		if err := TdhGetProperty(e.EventRec, 0, nil, 1, &dataDescriptor, propertySize, (*byte)(unsafe.Pointer(&length))); err != nil {
			return 0, fmt.Errorf("failed to get property: %s", err)
		}

		return length, nil
	}

	if epi.Length() > 0 {
		return epi.Length(), nil
	} else {
		switch {
		// if there is an error returned here just try to add a switch case
		// with the proper in type
		case epi.InType() == TDH_INTYPE_BINARY &&
			epi.OutType() == TDH_OUTTYPE_IPV6 &&
			epi.Length() == 0 &&
			(epi.Flags&(PropertyParamLength|PropertyParamFixedLength)) == 0:
			// If the property is an IP V6 address, you must set the PropertyLength parameter to the size
			// of the IN6_ADDR structure:
			// https://docs.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhformatproperty#remarks
			// sizeof(IN6_ADDR) == 16
			return 16, nil
		// NOTE(tekert): redundant? was 'return uint32(epi.Length()), nil' before
		case epi.InType() == TDH_INTYPE_UNICODESTRING:
			return 0, nil
		case epi.InType() == TDH_INTYPE_ANSISTRING:
			return 0, nil
		case epi.InType() == TDH_INTYPE_SID:
			return 0, nil
		case epi.InType() == TDH_INTYPE_WBEMSID:
			return 0, nil
		case epi.Flags&PropertyStruct == PropertyStruct:
			return 0, nil
		default:
			return 0, fmt.Errorf("unexpected length of 0 for intype %d and outtype %d", epi.InType(), epi.OutType())
		}

	}
}

func (e *EventRecordHelper) getPropertySize(i uint32) (size uint32, err error) {
	dataDesc := PropertyDataDescriptor{}
	dataDesc.PropertyName = uint64(e.TraceInfo.PropertyNameOffset(i))
	dataDesc.ArrayIndex = math.MaxUint32
	err = TdhGetPropertySize(e.EventRec, 0, nil, 1, &dataDesc, &size)
	return
}

// ========================================================================
// OLD FUNCTIONS, delete them later

func (e *EventRecordHelper) getArraySize_old(i uint32) (arraySize uint16, err error) {
	dataDesc := PropertyDataDescriptor{}
	propSz := uint32(0)

	epi := e.TraceInfo.GetEventPropertyInfoAt(i)
	if (epi.Flags & PropertyParamCount) == PropertyParamCount {
		count := uint32(0)
		j := epi.CountUnion
		dataDesc.PropertyName = uint64(e.TraceInfo.pointer() + uintptr(e.TraceInfo.GetEventPropertyInfoAt(uint32(j)).NameOffset))
		dataDesc.ArrayIndex = math.MaxUint32
		if err = TdhGetPropertySize(e.EventRec, 0, nil, 1, &dataDesc, &propSz); err != nil {
			return
		}
		if err = TdhGetProperty(e.EventRec, 0, nil, 1, &dataDesc, propSz, ((*byte)(unsafe.Pointer(&count)))); err != nil {
			return
		}
		arraySize = uint16(count)
	} else {
		arraySize = epi.CountUnion
	}
	return
}

func (e *EventRecordHelper) prepareProperty_old(i uint32) (p *Property, err error) {
	var size uint32

	p = &Property{}

	p.evtPropInfo = e.TraceInfo.GetEventPropertyInfoAt(i)
	p.evtRecordHelper = e
	p.name = UTF16AtOffsetToString(e.TraceInfo.pointer(), uintptr(p.evtPropInfo.NameOffset))
	p.pValue = e.userDataIt
	p.userDataLength = e.remainingUserDataLength()

	if p.length, err = e.getPropertyLength_old(i); err != nil {
		err = fmt.Errorf("failed to get property length: %s", err)
		return
	}

	// size is different from length
	if size, err = e.getPropertySize(i); err != nil {
		return
	}

	e.userDataIt += uintptr(size)

	return
}

// ========================================================================

// Helps when a nested property length needs to be calculated using a previous property value
// This has to be called on every TopLevelProperty index or Structure index
func (e *EventRecordHelper) cacheIntergerValues(i uint32) {
	epi := e.epiArray[i]
	// If this property is a scalar integer, remember the value in case it
	// is needed for a subsequent property's length or count.
	// This is a Single Value property, not a struct and it doesn't have a param count
	// Basically: if !isStruct && !hasParamCount && isSingleValue
	if (epi.Flags&(PropertyStruct|PropertyParamCount)) == 0 &&
		epi.Count() == 1 {

		// integerValues is used secuentally, so we can reuse it without reseting
		switch inType := TdhInType(epi.InType()); inType {
		case TDH_INTYPE_INT8:
		case TDH_INTYPE_UINT8:
			if (e.userDataEnd - e.userDataIt) >= 1 {
				e.integerValues[i] = uint16(*(*uint8)(unsafe.Pointer(e.userDataIt)))
			}
		case TDH_INTYPE_INT16:
		case TDH_INTYPE_UINT16:
			if (e.userDataEnd - e.userDataIt) >= 2 {
				e.integerValues[i] = *(*uint16)(unsafe.Pointer(e.userDataIt))
			}
		case TDH_INTYPE_INT32:
		case TDH_INTYPE_UINT32:
		case TDH_INTYPE_HEXINT32:
			if (e.userDataEnd - e.userDataIt) >= 4 {
				val := *(*uint32)(unsafe.Pointer(e.userDataIt))
				if val > 0xffff {
					e.integerValues[i] = 0xffff
				} else {
					e.integerValues[i] = uint16(val)
				}
			}
		}
	}
}

// Caches pointer values
func (e *EventRecordHelper) getEpiAt(i uint32) *EventPropertyInfo {
	// (epiArray mem is reused, make sure the elements are set to nil before use)
	if e.epiArray[i] == nil {
		e.epiArray[i] = e.TraceInfo.GetEventPropertyInfoAt(i)
		e.cacheIntergerValues(i)
	}
	return e.epiArray[i]
}

func (e *EventRecordHelper) debugDelete(epi *EventPropertyInfo) { //! TESTING
	// TDH_INTYPE_WBEMSID | TDH_INTYPE_SID   first few bytes (getProepertySize)

	// TDH_INTYPE_HEXDUMP reading the first four bytes

	// TDH_INTYPE_MANIFEST_COUNTEDBINARY   reading the first two bytes of the payload
	// TDH_INTYPE_BINARY  if length is 0, this is incorrectly encoded.

	// TDH_INTYPE_MANIFEST_COUNTEDSTRING reading the first two bytes of the payload
	// TDH_INTYPE_MANIFEST_COUNTEDANSISTRING reading the first two bytes of the payload
	// TDH_INTYPE_REVERSEDCOUNTEDANSISTRING  reading the first two bytes of the payload
	// TDH_INTYPE_REVERSEDCOUNTEDSTRING reading the first two bytes of the payload
	// TDH_INTYPE_COUNTEDANSISTRING reading the first two bytes of the payload
	// TDH_INTYPE_COUNTEDSTRING reading the first two bytes

	switch epi.InType() {
	case TDH_INTYPE_MANIFEST_COUNTEDSTRING:
		break
	case TDH_INTYPE_MANIFEST_COUNTEDANSISTRING:
		break
	case TDH_INTYPE_REVERSEDCOUNTEDANSISTRING:
		break
	case TDH_INTYPE_REVERSEDCOUNTEDSTRING:
		break
	case TDH_INTYPE_COUNTEDANSISTRING:
		break
	case TDH_INTYPE_COUNTEDSTRING:
		break

	case TDH_INTYPE_HEXDUMP:
		break

	case TDH_INTYPE_WBEMSID:
		break
	case TDH_INTYPE_SID:
		break

	case TDH_INTYPE_BINARY:
		if epi.OutType() != TDH_OUTTYPE_IPV6 {
			break
		}
	}
}

// Returns the length of the property at index i and the actual size in bytes.
func (e *EventRecordHelper) getPropertyLength(i uint32) (propLength uint16, sizeBytes uint32, err error) {
	var epi = e.getEpiAt(i)

	e.debugDelete(epi) //! TESTING

	// We recorded the values of all previous integer properties just
	// in case we need to determine the property length or count.
	// integerValues will have our length or count number.
	switch {
	case (epi.Flags & PropertyParamLength) != 0:
		// Length from another property
		propLength = e.integerValues[epi.LengthPropertyIndex()]

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

	// Improves performance (vs calling TdhGetPropertySize on every variable prop by ~6%)
	// We do this the long way to not abuse cgo calls on every prop.
	// (if go cgo improves in performance this will a 3 liner)
	// Handle zero length cases (null-terminated or variable)
	if propLength == 0 {
		// (taken from source comments)
		switch {
		case epi.OutType() == TDH_OUTTYPE_IPV6 &&
			epi.InType() == TDH_INTYPE_BINARY &&
			epi.Length() == 0 &&
			(epi.Flags&(PropertyParamLength|PropertyParamFixedLength)) == 0:
			propLength = 16 // special case for incorrectly-defined IPV6 addresses
			sizeBytes = 16

		// To advance the user data pointer we need the correct size.
		// TdgGetPropertySize doesn't give correct sizes for null terminated strings.
		case epi.InType() == TDH_INTYPE_UNICODESTRING:
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
			return 0, sizeBytes, nil

		case epi.InType() == TDH_INTYPE_ANSISTRING:
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
			return 0, sizeBytes, nil

		case epi.InType() == TDH_INTYPE_SID ||
			epi.InType() == TDH_INTYPE_WBEMSID:
			break // Use TdhGetPropertySize

		case epi.Flags&PropertyStruct == PropertyStruct:
			break // Use TdhGetPropertySize

		case ((epi.InType() == TDH_INTYPE_BINARY ||
			epi.InType() == TDH_INTYPE_HEXDUMP) &&
			epi.OutType() == TDH_OUTTYPE_HEXBINARY):
			break // the field is incorrectly encoded. NOTE(will be decoded in string form as "0x")

		default:
			slog.Warn("unexpected length of 0", "intype", epi.InType(), "outtype", epi.OutType())
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
	p.userDataLength = e.remainingUserDataLength()
	p.length, p.sizeBytes, err = e.getPropertyLength(i)
	if err != nil {
		return
	}

	// p.length has to be 0 on strings and structures for TdhFormatProperty to work.
	// We use size instead to advance when p.length is 0.
	e.userDataIt += uintptr(p.sizeBytes)

	return
}

// For debugging purposes, this is slower (not by much) but has the same problems with Kernel SystemConfig MOF Strings.
func (e *EventRecordHelper) getMOFStringProperty_old_delete(i uint32, arrayCount uint16) (value []uint16) {
	epi := e.getEpiAt(i)

	dataDescriptor := PropertyDataDescriptor{}
	// Get pointer to property name
	dataDescriptor.PropertyName = uint64(e.TraceInfo.pointer()) + uint64(epi.NameOffset)
	dataDescriptor.ArrayIndex = math.MaxUint32
	var propertySize uint32
	var err error
	err = TdhGetPropertySize(e.EventRec, 0, nil, 1, &dataDescriptor, &propertySize)
	if err != nil {
		return
	}

	buff := make([]byte, propertySize)
	err = TdhGetProperty(e.EventRec, 0, nil, 1, &dataDescriptor, propertySize, (*byte)(unsafe.Pointer(&buff[0])))
	if err != nil {
		fmt.Println("failed to get property: ", err)
		return
	}

	offset := uintptr(propertySize) // this is valid too (tested) = arrayCount*2
	//offset := (uintptr(arrayCount) * unsafe.Sizeof(uint16(0)))
	_ = offset
	//e.userDataIt += offset

	return *(*[]uint16)(unsafe.Pointer(&buff))
}

// Fastest way to get the MOF string, since is going to be converted we use slice (no copy).
// ~2.2% faster on big number of kernel events from file. and 1 less memory allocation.
// TdhGetPropertySize returns the same size as the arrayCount*2. (tested on all props)
// TdhGetProperty returns wrong data, so we have to read it manually.
// length = the number of elements in the array of EventPropertyInfo.
func (e *EventRecordHelper) getMOFStringProperty(length uint16) (mofString []uint16) {
	// UTF16 to UTF8 conversion will remove the data past the null terminator
	// No need to calculate where is the null termiantor here.
	// for some string types the length includes the null terminator
	mofString = unsafe.Slice((*uint16)(unsafe.Pointer(e.userDataIt)), length)
	return
}

// Prepare will partially decode the event, extracting event info for later
// This is a performance optimization to avoid decoding the event values now.
//
// There is a lot of information available in the event even without decoding,
// including timestamp, PID, TID, provider ID, activity ID, and the raw data.
func (e *EventRecordHelper) prepareProperties() (last error) {
	var p *Property

	// https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header
	if (e.EventRec.EventHeader.Flags & EVENT_HEADER_FLAG_STRING_ONLY) != 0 {
		// If there aren't any event property info structs, use the UserData directly.
		// NOTE: Does this flag mean that TraceInfo will be null too?
		if e.TraceInfo.TopLevelPropertyCount == 0 {
			str := (*uint16)(unsafe.Pointer(e.EventRec.UserData))
			value := syscall.UTF16ToString(
				unsafe.Slice(str, e.EventRec.UserDataLength/2))

			e.SetProperty("String", value)
		}
	}
	// if (e.EventRec.EventHeader.Flags & EVENT_HEADER_FLAG_TRACE_MESSAGE) != 0 {
	// }
	// if (e.EventRec.EventHeader.Flags & EVENT_HEADER_FLAG_CLASSIC_HEADER) != 0 {
	//	// Kernel events
	// }

	for i := uint32(0); i < e.TraceInfo.TopLevelPropertyCount; i++ {
		epi := e.getEpiAt(i)

		// Number of elements in the array of EventPropertyInfo.
		var arrayCount uint16
		if (epi.Flags & PropertyParamCount) != 0 {
			// Look up the value of a previous property
			arrayCount = e.integerValues[epi.CountPropertyIndex()]
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

		var array []*Property = make([]*Property, 0)
		var arrayName string
		var mofString []uint16

		// Treat non-array properties as arrays with one element.
		for arrayIndex := uint16(0); arrayIndex < arrayCount; arrayIndex++ {
			if isArray {
				LogTrace("Processing array element", "name", p.name, "index", arrayIndex)

				if arrayName == "" {
					arrayName = UTF16AtOffsetToString(e.TraceInfo.pointer(), uintptr(epi.NameOffset))
				}

				// if this is a MOF event, we don't need to parse the properties of the array
				// this will be a array of wchars, Kernel events EVENT_HEADER_FLAG_CLASSIC_HEADER
				if e.TraceInfo.IsMof() {
					if e.EventRec.EventHeader.Flags&EVENT_HEADER_FLAG_CLASSIC_HEADER != 0 {
						if epi.InType() == TDH_INTYPE_UNICODECHAR {
							//mofString = e.getMOFStringProperty_old_delete(i, arrayCount)
							mofString = e.getMOFStringProperty(arrayCount)
							e.userDataIt += (uintptr(arrayCount) * unsafe.Sizeof(uint16(0)))
							break // No need to parse the rest of the array
						}
					}
				} else {
					if p, last = e.prepareProperty(i); last != nil {
						return
					}
					array = append(array, p)
				}
			}

			if epi.Flags&PropertyStruct != 0 {
				// If this property is a struct, process the child properties
				slog.Debug("Processing struct property", "index", arrayIndex)

				//propStruct := make(map[string]*Property)
				propStruct := propertyMapPool.Get().(map[string]*Property)

				startIndex := epi.StructStartIndex()
				lastMember := startIndex + epi.NumOfStructMembers()

				for j := startIndex; j < lastMember; j++ {
					LogTrace("parsing struct property", "struct_index", j)
					// TODO: test this
					if p, last = e.prepareProperty(uint32(j)); last != nil {
						return
					} else {
						propStruct[p.name] = p
					}
				}

				e.Structures = append(e.Structures, propStruct)

				continue
			}

			// Single value that is not a struct.
			if arrayCount == 1 && !isArray {
				LogTrace("parsing scalar property", "index", i)
				if p, last = e.prepareProperty(i); last != nil {
					return
				}
				e.Properties[p.name] = p
			}
		}

		if mofString != nil {
			// This is a array of wchars, so put it in custom property
			value := syscall.UTF16ToString(mofString)
			e.SetProperty(arrayName, value)
		}

		if len(array) > 0 {
			e.ArrayProperties[arrayName] = array
		}
	}

	// if the last property did not reach the end of UserData, warning.
	if e.userDataIt < e.userDataEnd {
		if !e.TraceInfo.IsMof() { // MOF events always have extra data, is for align?
			slog.Debug("UserData not fully parsed", "remaining", e.userDataEnd-e.userDataIt)
		}
	}

	return
}

// ! NOTE(tekert) new method is 2x faster than this one
func (e *EventRecordHelper) prepareProperties_old() (last error) {
	var arraySize uint16
	var p *Property

	for i := uint32(0); i < e.TraceInfo.TopLevelPropertyCount; i++ {
		epi := e.TraceInfo.GetEventPropertyInfoAt(i)
		isArray := epi.Flags&PropertyParamCount == PropertyParamCount

		switch {
		case isArray:
			slog.Debug("Property is an array")
		case epi.Flags&PropertyParamLength == PropertyParamLength:
			slog.Debug("Property is a buffer")
		case epi.Flags&PropertyStruct == PropertyStruct:
			slog.Debug("Property is a struct")
		default:
			// property is a map
		}

		if arraySize, last = e.getArraySize_old(i); last != nil {
			return
		}

		var arrayName string
		var array []*Property

		// this is not because we have arraySize > 0 that we are an array
		// so if we deal with an array property
		if isArray {
			array = make([]*Property, 0)
		}

		for k := uint16(0); k < arraySize; k++ {

			// If the property is a structure
			if epi.Flags&PropertyStruct == PropertyStruct {
				slog.Debug("structure over here")
				propStruct := make(map[string]*Property)
				lastMember := epi.StructStartIndex() + epi.NumOfStructMembers()

				for j := epi.StructStartIndex(); j < lastMember; j++ {
					slog.Debug("parsing struct property", "index", j)
					if p, last = e.prepareProperty_old(uint32(j)); last != nil {
						return
					} else {
						propStruct[p.name] = p
					}
				}

				e.Structures = append(e.Structures, propStruct)

				continue
			}

			if p, last = e.prepareProperty_old(i); last != nil {
				return
			}

			if isArray {
				arrayName = p.name
				array = append(array, p)
				continue
			}

			e.Properties[p.name] = p
		}

		if len(array) > 0 {
			e.ArrayProperties[arrayName] = array
		}

	}

	return
}

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
	if props, ok := e.ArrayProperties[name]; ok {
		values := make([]string, len(props))

		// iterate over the properties
		for _, p := range props {
			var v string
			if v, err = p.FormatToString(); err != nil {
				return fmt.Errorf("%w array %s: %s", ErrPropertyParsing, name, err)
			}

			values = append(values, v)
		}

		eventData[name] = values
	}

	// parsing structures
	if name == StructurePropertyName {
		if len(e.Structures) > 0 {
			structs := make([]map[string]string, len(e.Structures))
			for _, m := range e.Structures {
				s := make(map[string]string)
				for field, prop := range m {
					if s[field], err = prop.FormatToString(); err != nil {
						return fmt.Errorf("%w %s.%s: %s", ErrPropertyParsing, StructurePropertyName, field, err)
					}
				}
			}

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

func (e *EventRecordHelper) parseAndSetAllProperties(out *Event) (last error) {
	var err error

	eventData := out.EventData

	// it is a user data property
	if (e.TraceInfo.Flags & TEMPLATE_USER_DATA) == TEMPLATE_USER_DATA {
		eventData = out.UserData
	}

	// Properties
	for pname, p := range e.Properties {
		if !e.shouldParse(pname) {
			continue
		}
		/*if err := e.parseAndSetProperty(pname, out); err != nil {
			last = err
		}*/
		if eventData[p.name], err = p.FormatToString(); err != nil {
			last = fmt.Errorf("%w %s: %s", ErrPropertyParsing, p.name, err)
		}
	}

	// Arrays
	for pname, props := range e.ArrayProperties {
		if !e.shouldParse(pname) {
			continue
		}

		values := make([]string, len(props))

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

	// Structure
	if !e.shouldParse(StructurePropertyName) {
		return
	}

	if len(e.Structures) > 0 {
		structs := make([]map[string]string, len(e.Structures))
		for _, m := range e.Structures {
			s := make(map[string]string)
			for field, prop := range m {
				if s[field], err = prop.FormatToString(); err != nil {
					last = fmt.Errorf("%w %s.%s: %s", ErrPropertyParsing, StructurePropertyName, field, err)
				}
			}
		}

		eventData[StructurePropertyName] = structs
	}

	return
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

// slower version of: [EventRecordHelper.GetPropertyInt]
func (e *EventRecordHelper) GetPropertyStringInt(name string) (i int64, err error) {
	var s string
	if s, err = e.GetPropertyString(name); err != nil {
		return
	}

	return strconv.ParseInt(s, 0, 64)
}

func (e *EventRecordHelper) GetPropertyInt(name string) (i int64, err error) {
	if p, ok := e.Properties[name]; ok {
		return p.GetInt()
	}
	return 0, fmt.Errorf("%w %s", ErrUnknownProperty, name)
}

// slower version of: [EventRecordHelper.GetPropertyUint]
func (e *EventRecordHelper) GetPropertyStringUint(name string) (u uint64, err error) {
	var s string

	if s, err = e.GetPropertyString(name); err != nil {
		return
	}

	return strconv.ParseUint(s, 0, 64)
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

func (e *EventRecordHelper) SetProperty(name, value string) {
	if p, ok := e.Properties[name]; ok {
		p.value = value
		return
	}

	p := getProperty()
	p.name = name
	p.value = value
	e.Properties[name] = p
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
	if props, ok := e.ArrayProperties[name]; ok {
		// iterate over the properties
		for _, p := range props {
			if _, err = p.FormatToString(); err != nil {
				return fmt.Errorf("%w array %s: %s", ErrPropertyParsing, name, err)
			}
		}
	}

	// parsing structures
	if name == StructurePropertyName {
		if len(e.Structures) > 0 {
			for _, m := range e.Structures {
				s := make(map[string]string)
				for field, prop := range m {
					if s[field], err = prop.FormatToString(); err != nil {
						return fmt.Errorf("%w %s.%s: %s", ErrPropertyParsing, StructurePropertyName, field, err)
					}
				}
			}
		}
	}

	return
}

func (e *EventRecordHelper) Skippable() {
	e.Flags.Skippable = true
}

func (e *EventRecordHelper) Skip() {
	e.Flags.Skip = true
}
