//go:build windows
// +build windows

package etw

type MofKernelNames struct {
	// Class name
	Name string
	// Serves as base to compute event id
	BaseId uint16
}

var (
	// The final event id of Mof Events is computed
	// by BaseId + Opcode. As Opcode is uint8 we jump
	// BaseIds every 0xff so that we do not overlap event
	// ids between classes
	MofClassMapping = map[uint32]MofKernelNames{
		guidToUint("45d8cccd-539f-4b72-a8b7-5c683142609a"): {Name: "ALPC", BaseId: /*0*/ calcBaseId(0)},
		guidToUint("78d14f17-0105-46d7-bfff-6fbea2f3f358"): {Name: "ApplicationVerifier", BaseId: /*255*/ calcBaseId(1)},
		guidToUint("13976d09-a327-438c-950b-7f03192815c7"): {Name: "DbgPrint", BaseId: /*510*/ calcBaseId(2)},
		guidToUint("3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c"): {Name: "DiskIo", BaseId: /*765*/ calcBaseId(3)},
		guidToUint("bdd865d1-d7c1-11d0-a501-00a0c9062910"): {Name: "DiskPerf", BaseId: /*1020*/ calcBaseId(4)},
		guidToUint("d56ca431-61bf-4904-a621-00e0381e4dde"): {Name: "DriverVerifier", BaseId: /*1275*/ calcBaseId(5)},
		guidToUint("b16f9f5e-b3da-4027-9318-adf2b79df73b"): {Name: "EventLog", BaseId: /*1530*/ calcBaseId(6)},
		guidToUint("01853a65-418f-4f36-aefc-dc0f1d2fd235"): {Name: "EventTraceConfig", BaseId: /*1785*/ calcBaseId(7)},
		guidToUint("90cbdc39-4a3e-11d1-84f4-0000f80464e3"): {Name: "FileIo", BaseId: /*2040*/ calcBaseId(8)},
		guidToUint("8d40301f-ab4a-11d2-9a93-00805f85d7c6"): {Name: "GenericMessage", BaseId: /*2295*/ calcBaseId(9)},
		guidToUint("e8908abc-aa84-11d2-9a93-00805f85d7c6"): {Name: "GlobalLogger", BaseId: /*2550*/ calcBaseId(10)},
		guidToUint("3d6fa8d2-fe05-11d0-9dda-00c04fd7ba7c"): {Name: "HardFault", BaseId: /*2805*/ calcBaseId(11)},
		guidToUint("2cb15d1d-5fc1-11d2-abe1-00a0c911f518"): {Name: "ImageLoad", BaseId: /*3060*/ calcBaseId(12)},
		guidToUint("98a2b9d7-94dd-496a-847e-67a5557a59f2"): {Name: "MsSystemInformation", BaseId: /*3315*/ calcBaseId(13)},
		guidToUint("3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c"): {Name: "PageFault", BaseId: /*3570*/ calcBaseId(14)},
		guidToUint("ce1dbfb4-137e-4da6-87b0-3f59aa102cbc"): {Name: "PerfInfo", BaseId: /*3825*/ calcBaseId(15)},
		guidToUint("3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c"): {Name: "Process", BaseId: /*4080*/ calcBaseId(16)},
		guidToUint("ae53722e-c863-11d2-8659-00c04fa321a1"): {Name: "Registry", BaseId: /*4335*/ calcBaseId(17)},
		guidToUint("d837ca92-12b9-44a5-ad6a-3a65b3578aa8"): {Name: "SplitIo", BaseId: /*4590*/ calcBaseId(18)},
		guidToUint("9a280ac0-c8e0-11d1-84e2-00c04fb998a2"): {Name: "TcpIp", BaseId: /*4845*/ calcBaseId(19)},
		guidToUint("a1bc18c0-a7c8-11d1-bf3c-00a0c9062910"): {Name: "ThermalZone", BaseId: /*5100*/ calcBaseId(20)},
		guidToUint("3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c"): {Name: "Thread", BaseId: /*5355*/ calcBaseId(21)},
		guidToUint("398191dc-2da7-11d3-8b98-00805f85d7c6"): {Name: "TraceError", BaseId: /*5610*/ calcBaseId(22)},
		guidToUint("bf3a50c5-a9c9-4988-a005-2df0b7c80f80"): {Name: "UdpIp", BaseId: /*5865*/ calcBaseId(23)},
		guidToUint("44608a51-1851-4456-98b2-b300e931ee41"): {Name: "WmiEventLogger", BaseId: /*6120*/ calcBaseId(24)},
		guidToUint("68fdd900-4a3e-11d1-84f4-0000f80464e3"): {Name: "EventTraceEvent", BaseId: /*6375*/ calcBaseId(25)},
	}
)

func calcBaseId(index int) uint16 {
	return uint16(index * 0xFF)
}

func guidToUint(guid string) uint32 {
	u := MustParseGUID(guid)
	// Take first 4 bytes of GUID and convert to uint32
	return u.Data1
}

var (
	mofClassLookupMap = make(map[uint64]*MofClassDef) // Lookup by packed key
	MofClassQueryMap  = make(map[string]*MofClassDef) // Lookup by class name

	mofKernelClassLoaded = false
)

// Represents a MOF property definition
type MofPropertyDef struct {
	ID         uint16 // WmiDataId
	Name       string
	InType     TdhInType  // How to read the raw data
	OutType    TdhOutType // How to represent in Go
	IsArray    bool
	ArraySize  uint32 // MAX(n)
	SizeFromID uint32 // WmiSizeIs("PropName") - ID of property that holds array size
}

// MofClassDef represents a complete MOF class definition
type MofClassDef struct {
	Name       string           // Class name (e.g. "Process_V2_TypeGroup1")
	Base       string           // Base class name (e.g. "Process_V2")
	GUID       GUID             // From parent class
	Version    uint8            // From parent class
	EventTypes []uint8          // List of event types this class handles
	Properties []MofPropertyDef // Property definitions
}

// MofRegister adds a MOF class definition to the global MofClassQueryMap
// and mofClassLookupMap maps.
// Used to load kernel MOF classes when the package is initialized
func MofRegister(class *MofClassDef) {
	for _, eventType := range class.EventTypes {
		key := MofPackKey(class.GUID.Data1, class.GUID.Data2, eventType, class.Version)
		mofClassLookupMap[key] = class
	}

	// Register for lookup by name
	MofClassQueryMap[class.Name] = class
}

// MofLookup finds a MOF class definition by its event record
// A MOF event record is uniquely identified by its provider GUID, event type, and version
func MofErLookup(er *EventRecord) *MofClassDef {
	key := MofPackKey(er.EventHeader.ProviderId.Data1, // guid first 32 bits
		er.EventHeader.ProviderId.Data2,        // guid second 16 bits
		er.EventHeader.EventDescriptor.Opcode,  // EventType 8 bytes
		er.EventHeader.EventDescriptor.Version) // EventVersion 8 bytes

	class, exists := mofClassLookupMap[key]

	if !exists {
		return nil
	}
	return class
}

// MofLookup finds a MOF class definition by its identifiers
// A MOF event record is uniquely identified by its provider GUID, event type, and version
func MofLookup(guid GUID, eventType uint8, version uint8) *MofClassDef {
	key := MofPackKey(guid.Data1, guid.Data2, eventType, version)
	class, exists := mofClassLookupMap[key]
	if !exists {
		return nil
	}
	return class
}

// Bit positions for packing/unpacking
const (
	bGUID_DATA1_SHIFT = 32 // ProviderId (Data1) uses bits 32-63
	bGUID_DATA2_SHIFT = 16 // ProviderId (Data2) uses bits 16-31
	bOPCODE_SHIFT     = 8  // Opcode uses bits 8-15
	bVERSION_SHIFT    = 0  // Version uses lower 8 bits
)

// Pack event identifiers into single uint64
func MofPackKey(providerId uint32, data2 uint16, opcode uint8, version uint8) uint64 {
	return uint64(providerId)<<bGUID_DATA1_SHIFT |
		uint64(data2)<<bGUID_DATA2_SHIFT |
		uint64(opcode)<<bOPCODE_SHIFT |
		uint64(version)<<bVERSION_SHIFT
}

// Unpack for debugging/display
func MofUnpackKey(key uint64) (providerId uint32, data2 uint16, opcode uint8, version uint8) {
	providerId = uint32(key >> bGUID_DATA1_SHIFT)
	data2 = uint16((key >> bGUID_DATA2_SHIFT) & 0xFFFF)
	opcode = uint8((key >> bOPCODE_SHIFT) & 0xFF)
	version = uint8(key & 0xFF)
	return
}

// Loads custom kernel MOF classes into the global registry (only for parsing purposes)
func init() {

	// Event 84 is not defined in the kernel MOF classes or the web, but maybe it's a special event
	// from the hex data, the only similar event is FileIo_Info
	/* UsarData Memory Dump examples (40 bytes):
	f810d5710ad2ffff 5037b76f0ad2ffff 00c7b1bf8cbeffff 0000000000000000 dc700000 00000000
	38717b760ad2ffff d043b76f0ad2ffff 00c7b1bf8cbeffff 0000000000000000 a42d0000 00000000
	f8403a7b0ad2ffff a064b76f0ad2ffff 00c7b1bf8cbeffff 0000000000000000 94760000 00000000
	f8708f6d0ad2ffff d043b76f0ad2ffff 00c7b1bf8cbeffff 0000000000000000 4c550000 00000000
	f8403a7b0ad2ffff a064b76f0ad2ffff 00c7b1bf8cbeffff 0000000000000000 94760000 00000000
	f810d5710ad2ffff c035b76f0ad2ffff 00c7b1bf8cbeffff 0000000000000000 dc700000 00000000
	IrpPtr           FileObject  	  FileKey          ?                TTID?    InfoClass?
	*/
	// TODO(tekert): Find the correct definition for this event
	var FileIo_V3_Type84 = &MofClassDef{
		Name:       "FileIo_Type84",
		Base:       "FileIo",
		GUID:       mofFileIo.GUID,
		Version:    3,
		EventTypes: []uint8{84},
		Properties: []MofPropertyDef{
			{ID: 1, Name: "IrpPtr", InType: TDH_INTYPE_POINTER},
			{ID: 2, Name: "FileObject", InType: TDH_INTYPE_POINTER},
			{ID: 3, Name: "FileKey", InType: TDH_INTYPE_POINTER},
			{ID: 4, Name: "ExtraInfo", InType: TDH_INTYPE_POINTER},
			{ID: 5, Name: "TTID", InType: TDH_INTYPE_UINT32},
			{ID: 6, Name: "InfoClass", InType: TDH_INTYPE_UINT32},
		},
	}

	// Event 33 is not defined in the kernel MOF classes or the web, but maybe it's a special event
	// ?                 ?                  KeyHandle        KeyName
	// 00000000 00000000 00000000 00000000  605c8bda8cbeffff <unicode string>
	// TODO(tekert): Find the correct definition for this event
	var Registry_V2_Type33 = &MofClassDef{
		Name:       "Registry_Type33",
		Base:       "Registry",
		GUID:       *MustParseGUID("{ae53722e-c863-11d2-8659-00c04fa321a1}"), // Registry
		Version:    2,
		EventTypes: []uint8{33},
		Properties: []MofPropertyDef{
			{ID: 1, Name: "InitialTime", InType: TDH_INTYPE_INT64},
			{ID: 2, Name: "Status", InType: TDH_INTYPE_UINT32},
			{ID: 3, Name: "Index", InType: TDH_INTYPE_UINT32},
			{ID: 4, Name: "KeyHandle", InType: TDH_INTYPE_POINTER},
			{ID: 5, Name: "KeyName", InType: TDH_INTYPE_UNICODESTRING, OutType: TDH_OUTTYPE_STRING},
		},
	}

	MofRegister(FileIo_V3_Type84)
	MofRegister(Registry_V2_Type33)

}
