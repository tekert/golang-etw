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

	// Property buffer pool to reuse Property structs
	// Can be reused multiple times for every new event record.
	propertyPool = sync.Pool{
		New: func() interface{} {
			return &Property{}
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
)

type Property struct {
	evtRecordHelper *EventRecordHelper
	evtPropInfo     *EventPropertyInfo

	name   string
	value  string
	length uint16

	pValue         uintptr
	userDataLength uint16
}

// Sets all fields of the struct to zero/empty values
func (p *Property) reset() {
	*p = Property{}
}

func (p *Property) release() {
	//p.reset() // Better to reset before use and not release.
	propertyPool.Put(p)
}

func maxu32(a, b uint32) uint32 {
	if a < b {
		return b
	}
	return a
}

func (p *Property) Parseable() bool {
	return p.evtRecordHelper != nil && p.evtPropInfo != nil && p.pValue > 0
}

func (p *Property) Value() (string, error) {
	var err error

	if p.value == "" && p.Parseable() {
		// we parse only if not already done
		p.value, err = p.parse()
	}

	return p.value, err
}

func (p *Property) parse() (value string, err error) {
	var mapInfo *EventMapInfo
	var udc uint16
	var buff []uint16

	formattedDataSize := maxu32(16, uint32(p.length))

	// Get the name/value mapping if the property specifies a value map.
	if p.evtPropInfo.MapNameOffset() > 0 {
		switch p.evtPropInfo.InType() {
		case TDH_INTYPE_UINT8,
			TDH_INTYPE_UINT16,
			TDH_INTYPE_UINT32,
			TDH_INTYPE_HEXINT32:
			pMapName := (*uint16)(unsafe.Pointer(p.evtRecordHelper.TraceInfo.pointerOffset(uintptr(p.evtPropInfo.MapNameOffset()))))
			decSrc := p.evtRecordHelper.TraceInfo.DecodingSource
			if mapInfo, err = p.evtRecordHelper.EventRec.GetMapInfo(pMapName, uint32(decSrc)); err != nil {
				err = fmt.Errorf("failed to get map info: %s", err)
				return
			}
		}
	}

	for {

		buff = make([]uint16, formattedDataSize)

		if p.length == 0 && p.evtPropInfo.InType() == TDH_INTYPE_NULL {
			// TdhFormatProperty doesn't handle INTYPE_NULL.
			buff[0] = 0
			err = nil
		} else if p.length == 0 &&
			(p.evtPropInfo.Flags&(PropertyParamLength|PropertyParamFixedLength)) != 0 &&
			(p.evtPropInfo.InType() == TDH_INTYPE_UNICODESTRING ||
				p.evtPropInfo.InType() == TDH_INTYPE_ANSISTRING) {
			// TdhFormatProperty doesn't handle zero-length counted strings.
			buff[0] = 0
			err = nil
		} else {
			err = TdhFormatProperty(
				p.evtRecordHelper.TraceInfo,
				mapInfo,
				p.evtRecordHelper.EventRec.PointerSize(),
				uint16(p.evtPropInfo.InType()),
				uint16(p.evtPropInfo.OutType()),
				p.length,
				p.userDataLength,
				(*byte)(unsafe.Pointer(p.pValue)),
				&formattedDataSize,
				&buff[0],
				&udc)
		}

		if err == syscall.ERROR_INSUFFICIENT_BUFFER {
			continue
		}

		if err == ERROR_EVT_INVALID_EVENT_DATA {
			if mapInfo == nil {
				break
			}
			mapInfo = nil
			continue
		}

		if err == nil {
			break
		}

		err = fmt.Errorf("failed to format property: Event Details:\n"+
			"Property Name: %s\n"+
			"Property Type: InType=%d, OutType=%d\n"+
			"Property Length: %d\n"+
			"Provider: %s\n"+
			"Event ID: %d\n"+
			"Original Error: %s\n",
			//"Last Props: %s",
			p.name,
			p.evtPropInfo.InType(),
			p.evtPropInfo.OutType(),
			p.length,
			p.evtRecordHelper.Provider(),
			p.evtRecordHelper.EventID(),
			err)
		//history.String()) // Add history to error message)

		//err = fmt.Errorf("failed to format property : %s", err)
		return
	}

	value = syscall.UTF16ToString(buff)

	return
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

	// Buffer that contains the memory for TraceEventInfo
	// used internally to reuse the memory allocation.
	teiPoolBuffer *[]byte

	// Position of the next byte of event data to be consumed.
	// increments after each call to prepareProperty
	userDataIt uintptr

	// Position of the end of the event data
	// For UserData length check [.EventRec.UserDataLength]
	userDataEnd uintptr

	selectedProperties map[string]bool
}

func (e *EventRecordHelper) reset() {
	*e = EventRecordHelper{}
	// maps and slices are already reseted when released
}

func (e *EventRecordHelper) remainingUserDataLength() uint16 {
	return uint16(e.userDataEnd - e.userDataIt)
}

// Creates a new EventRecordHelper that has the EVENT_RECORD and gets a TRACE_EVENT_INFO for that event.
func newEventRecordHelper(er *EventRecord) (erh *EventRecordHelper, err error) {
	erh = eventRecordHelperPool.Get().(*EventRecordHelper)
	// reset fields to avoid stale data
	erh.reset()

	erh.EventRec = er

	if erh.TraceInfo, erh.teiPoolBuffer, err = er.GetEventInformation(); err != nil {
		err = fmt.Errorf("TdhGetEventInformation failed with 0x : %s", err)
	}

	return
}

// Release EventRecordHelper back to mem pool
// Including all the memory allocations that were made during the processing of the event
// (helps reduce memory allocations by reusing this memory)
func (e *EventRecordHelper) release() {
	// Since we have to release the property struct memory by iterating we may as well
	// reset the memory of the maps and slices while doing it

	// 1. Reset/Clear and return to the pool Properties map
	for k, p := range e.Properties {
		p.release()
		delete(e.Properties, k)
	}
	propertyMapPool.Put(e.Properties)

	// 2. Reset/Clear and return ArrayProperties to the pool
	for k, p := range e.ArrayProperties {
		for _, p := range p {
			p.release()
		}
		delete(e.ArrayProperties, k)
	}
	arrayPropertyMapPool.Put(e.ArrayProperties)

	// 3. Reset/Clear and return Structures to the pool
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

	// 4. Clear and return selectedProperties
	clear(e.selectedProperties)
	selectedPropertiesPool.Put(e.selectedProperties)

	// 5. Reset integerValues slice (keep capacity) and return to pool
	e.integerValues = e.integerValues[:0]
	integerValuesPool.Put(&e.integerValues)

	// 6. Reset epiArray slice (keep capacity) and return to pool
	for i := range e.epiArray { // important
		e.epiArray[i] = nil
	}
	e.epiArray = e.epiArray[:0]
	epiArrayPool.Put(&e.epiArray)

	// 7. Release back into the pool the mem allocation for TraceEventInfo
	tdhInfoPool.Put(e.teiPoolBuffer)

	// Last. Finally, Release this object memory
	eventRecordHelperPool.Put(e)
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
	//e.Properties = make(map[string]*Property, e.TraceInfo.TopLevelPropertyCount)
	//e.ArrayProperties = make(map[string][]*Property)
	//e.Structures = make([]map[string]*Property, 0)

	// This memory was already reseted when it was released.
	e.Properties = propertyMapPool.Get().(map[string]*Property)
	e.ArrayProperties = arrayPropertyMapPool.Get().(map[string][]*Property)
	e.Structures = *(structuresSlicePool.Get().(*[]map[string]*Property))

	// e.selectedProperties = make(map[string]bool)
	// e.integerValues = make([]uint16, e.TraceInfo.PropertyCount)
	// e.epiArray = make([]*EventPropertyInfo, e.TraceInfo.PropertyCount)

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

	// userDataIt iterator will be incremented for each queried property by length
	e.userDataIt = e.EventRec.UserData
	e.userDataEnd = e.EventRec.UserData + uintptr(e.EventRec.UserDataLength)
}

func (e *EventRecordHelper) setEventMetadata(event *Event) {
	event.System.Computer = hostname
	event.System.Execution.ProcessID = e.EventRec.EventHeader.ProcessId
	event.System.Execution.ThreadID = e.EventRec.EventHeader.ThreadId
	event.System.Execution.ProcessorID = uint16(e.EventRec.BufferContext.Processor)
	event.System.Execution.KernelTime = e.EventRec.EventHeader.GetKernelTime() // NOTE: for private session use e.EventRec.EventHeader.ProcessorTime
	event.System.Execution.UserTime = e.EventRec.EventHeader.GetUserTime()     // NOTE: for private session use e.EventRec.EventHeader.ProcessorTime
	event.System.Correlation.ActivityID = e.EventRec.EventHeader.ActivityId.String()
	relatedActivityID := e.EventRec.RelatedActivityID()
	if relatedActivityID.IsZero() {
		event.System.Correlation.RelatedActivityID = nullGUIDStr
	} else {
		event.System.Correlation.RelatedActivityID = relatedActivityID.String()
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

// =========================================================================================================================
// =========================================================================================================================
// =========================================================================================================================

// Helps when a nested property length needs to be calculated using a previous property value
// This has to be called on every TopLevelProperty index or Structure index
func (e *EventRecordHelper) cacheIntergerValues(i uint32) {
	// If this property is a scalar integer, remember the value in case it
	// is needed for a subsequent property's length or count.
	// This is a Single Value property, not a struct and it doesn't have a param count
	// Basically: if !isStruct && !hasParamCount && isSingleValue
	if (e.epiArray[i].Flags&(PropertyStruct|PropertyParamCount)) == 0 &&
		e.epiArray[i].Count() == 1 {

		// integerValues is used secuentally, so we can reuse it without reseting
		switch inType := TdhInType(e.epiArray[i].InType()); inType {
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
// TODO(tekert): check if the use of e.epiArray improves performance
func (e *EventRecordHelper) getEpiAt(i uint32) *EventPropertyInfo {
	// (epiArray mem is reused, make sure the elements are set to nil before use)
	if e.epiArray[i] == nil {
		e.epiArray[i] = e.TraceInfo.GetEventPropertyInfoAt(i)
		e.cacheIntergerValues(i)
	}
	return e.epiArray[i]
}

func (e *EventRecordHelper) getPropertyLength(i uint32) (propLength uint16, size uint32, err error) {
	var epi = e.getEpiAt(i)
	size = 0

	// We recorded the values of all previous integer properties just
	// in case we need to determine the property length or count.
	// integerValues will have our length or count number.
	// (Size of the property is in bytes)
	if epi.OutType() == TDH_OUTTYPE_IPV6 &&
		epi.InType() == TDH_INTYPE_BINARY &&
		epi.Length() == 0 &&
		(epi.Flags&(PropertyParamLength|PropertyParamFixedLength)) == 0 {
		propLength = 16 // special case for incorrectly-defined IPV6 addresses
	} else if (epi.Flags & PropertyParamLength) != 0 {
		propLength = e.integerValues[epi.LengthPropertyIndex()] // Look up the value of a previous property
	} else {
		propLength = epi.Length()
	}

	if propLength == 0 {
		// For details on every encoded size, read comments below TdhInType in 'tdh_headers.go'
		// The Intypes that can have a length of 0 are:
		// (taken from source comments)
		switch {
		case epi.InType() == TDH_INTYPE_UNICODESTRING:
			break
		case epi.InType() == TDH_INTYPE_ANSISTRING:
			break
		case epi.InType() == TDH_INTYPE_SID:
			break // First few bytes... It's the only type that doesn't specify details.
		case epi.InType() == TDH_INTYPE_WBEMSID:
			break // Deprecated but same as SID.
		case epi.Flags&PropertyStruct == PropertyStruct:
			break
		case (epi.InType()&(TDH_INTYPE_BINARY|TDH_INTYPE_HEXDUMP)) != 0 &&
			epi.OutType() == TDH_OUTTYPE_HEXBINARY:
			break // the field is incorrectly encoded.
		default:
			slog.Warn("unexpected length of 0", "intype", epi.InType(), "outtype", epi.OutType())
		}

		// *NOTE(tekert): We could get the sizes coding a new parser, we have all the data in the sources
		// It could improve performance, a heavy syscall less for every variadic property processed...
		// this can be called multiple times per event... if there are string for example.
		// in other words we could skip a call to getPropertySize here.
		size, err = e.getPropertySize(i)
		if err != nil {
			return
		}
	}

	return
}

func (e *EventRecordHelper) prepareProperty(i uint32) (p *Property, err error) {
	var userOffset uintptr
	var size uint32
	p = propertyPool.Get().(*Property)
	p.reset() // Important. Reset the property to avoid stale data

	p.evtPropInfo = e.getEpiAt(i)
	p.evtRecordHelper = e
	// the complexity of maintaining a stringCache is larger than the small cost it saves
	p.name = UTF16AtOffsetToString(e.TraceInfo.pointer(), uintptr(p.evtPropInfo.NameOffset))
	p.pValue = e.userDataIt
	p.userDataLength = e.remainingUserDataLength()
	p.length, size, err = e.getPropertyLength(i)
	if err != nil {
		return
	}

	// p.length has to be 0 on strings and structures
	// so we use size instead to advance when p.length is 0.
	if p.length == 0 {
		userOffset = uintptr(size)
	} else {
		userOffset = uintptr(p.length)
	}
	e.userDataIt += userOffset

	return
}

// There is a lot of information available in the event even without decoding,
// including timestamp, PID, TID, provider ID, activity ID, and the raw data.
func (e *EventRecordHelper) prepareProperties() (last error) {
	var p *Property

	// TODO: check for wpp event and handle it differently

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

		// Treat non-array properties as arrays with one element.
		for arrayIndex := uint16(0); arrayIndex < arrayCount; arrayIndex++ {
			if isArray {

				if p, last = e.prepareProperty(i); last != nil {
					return
				}
				slog.Debug("Processing array element", "name", p.name, "index", arrayIndex)

				arrayName = p.name
				array = append(array, p)
			}

			if epi.Flags&PropertyStruct != 0 {
				// If this property is a struct, process the child properties
				slog.Debug("Processing struct property", "index", arrayIndex)

				//propStruct := make(map[string]*Property)
				propStruct := propertyMapPool.Get().(map[string]*Property)
				//clear(propStruct) // memory is already reseted when it was released

				startIndex := epi.StructStartIndex()
				lastMember := startIndex + epi.NumOfStructMembers()

				for j := startIndex; j < lastMember; j++ {
					slog.Debug("parsing struct property", "struct_index", j)
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
				slog.Debug("parsing scalar property", "index", i)
				if p, last = e.prepareProperty(i); last != nil {
					return
				}
				e.Properties[p.name] = p
			}

			// MapInfo is needed when parsing using thd, not when preparing.
			/*
				// If the property has an associated map (i.e. an enumerated type),
				// try to look up the map data. (If this is an array, we only need
				// to do the lookup on the first iteration.)
				if epi.MapNameOffset() != 0 && arrayIndex == 0 {
					switch TdhInType(epi.InType()) {
					case TDH_INTYPE_UINT8,
						TDH_INTYPE_UINT16,
						TDH_INTYPE_UINT32,
						TDH_INTYPE_HEXINT32:

						e.TraceInfo.pointerOffset(uintptr(epi.MapNameOffset()))

						pMapName := (*uint16)(unsafe.Pointer(e.TraceInfo.pointerOffset(uintptr(epi.MapNameOffset()))))
						decSrc := p.evtRecordHelper.TraceInfo.DecodingSource
						if pMapInfo, err = p.evtRecordHelper.EventRec.GetMapInfo(pMapName, uint32(decSrc)); err != nil {
							err = fmt.Errorf("failed to get map info: %s", err)
							return
						}
						mapInfo = e.EventRec.GetMapInfo()
					}
				}
			*/
		}

		if len(array) > 0 {
			e.ArrayProperties[arrayName] = array
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
		if eventData[p.name], err = p.Value(); err != nil {
			return fmt.Errorf("%w %s: %s", ErrPropertyParsing, name, err)
		}
	}

	// parsing array
	if props, ok := e.ArrayProperties[name]; ok {
		values := make([]string, len(props))

		// iterate over the properties
		for _, p := range props {
			var v string
			if v, err = p.Value(); err != nil {
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
					if s[field], err = prop.Value(); err != nil {
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
		if eventData[p.name], err = p.Value(); err != nil {
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
			if v, err = p.Value(); err != nil {
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
				if s[field], err = prop.Value(); err != nil {
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
		return p.Value()
	}

	return "", fmt.Errorf("%w %s", ErrUnknownProperty, name)
}

func (e *EventRecordHelper) GetPropertyInt(name string) (i int64, err error) {
	var s string

	if s, err = e.GetPropertyString(name); err != nil {
		return
	}

	return strconv.ParseInt(s, 0, 64)
}

func (e *EventRecordHelper) GetPropertyUint(name string) (u uint64, err error) {
	var s string

	if s, err = e.GetPropertyString(name); err != nil {
		return
	}

	return strconv.ParseUint(s, 0, 64)
}

func (e *EventRecordHelper) SetProperty(name, value string) {

	if p, ok := e.Properties[name]; ok {
		p.value = value
		return
	}

	e.Properties[name] = &Property{name: name, value: value}
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
		if _, err = p.Value(); err != nil {
			return fmt.Errorf("%w %s: %s", ErrPropertyParsing, name, err)
		}
	}

	// parsing array
	if props, ok := e.ArrayProperties[name]; ok {
		// iterate over the properties
		for _, p := range props {
			if _, err = p.Value(); err != nil {
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
					if s[field], err = prop.Value(); err != nil {
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
