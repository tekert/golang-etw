//go:build windows
// +build windows

package etw

var GlobalMofRegistry = NewMofClassRegistry()

// MofClassKey uniquely identifies a MOF class definition
type MofClassKey struct {
	GUID      GUID   // Provider GUID
	EventType uint8  // Event type/opcode
	Version   uint16 // Schema version
}

// MofClassRegistry stores all registered MOF class definitions
type MofClassRegistry struct {
	classes map[MofClassKey]*MofClassDef
}

// NewMofClassRegistry creates a new registry
func NewMofClassRegistry() *MofClassRegistry {
	return &MofClassRegistry{
		classes: make(map[MofClassKey]*MofClassDef),
	}
}

// Register adds a class definition with its event type
// Register adds a MOF class definition to the registry
func (r *MofClassRegistry) Register(class *MofClassDef) {
	// Create an entry for each event type this class handles
	for _, eventType := range class.EventTypes {
		key := MofClassKey{
			GUID:      class.GUID,
			EventType: eventType,
			Version:   class.Version,
		}
		r.classes[key] = class
	}
}

// Lookup finds a class definition by its identifiers
func (r *MofClassRegistry) Lookup(guid GUID, eventType uint8, version uint16) *MofClassDef {
	key := MofClassKey{
		GUID:      guid,
		EventType: eventType,
		Version:   version,
	}
	return r.classes[key]
}

// Represents a MOF property definition
type MofPropertyDef struct {
	ID           uint16 // WmiDataId
	Name         string
	InType       TdhInType  // How to read the raw data
	OutType      TdhOutType // How to represent in Go
	IsArray      bool
	ArraySize    uint32 // MAX(n)
	SizeFromID  uint32 // WmiSizeIs("PropName") - property name
}

// MofClassDef represents a complete MOF class definition
type MofClassDef struct {
	Name       string           // Class name (e.g. "Process_V2_TypeGroup1")
	Base       string           // Base class name (e.g. "Process_V2")
	GUID       GUID             // From parent class
	Version    uint16           // From parent class
	EventTypes []uint8          // List of event types this class handles
	Properties []MofPropertyDef // Property definitions
}
