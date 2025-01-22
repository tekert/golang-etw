package etw

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

type EventID uint16

type Event struct {
	Flags struct {
		// Use to flag event as being skippable for performance reason
		Skippable bool
	} `json:"-"`

	EventData map[string]interface{} `json:",omitempty"`
	UserData  map[string]interface{} `json:",omitempty"`
	System    struct {
		Channel     string
		Computer    string
		EventID     uint16
		Version     uint8  `json:",omitempty"`
		EventType   string `json:",omitempty"`
		EventGuid   string `json:",omitempty"`
		Correlation struct {
			ActivityID        string
			RelatedActivityID string
		}
		Execution struct {
			ProcessID   uint32
			ThreadID    uint32
			ProcessorTime uint64 `json:",omitempty"`
			ProcessorID uint16
			KernelTime  uint32
			UserTime    uint32
		}
		Keywords Keywords // Change this line to use Keywords type
		// Keywords struct {
		// 	Mask uint64
		// 	Name []string
		// }
		Level struct {
			Value uint8
			Name  string
		}
		Opcode struct {
			Value uint8
			Name  string
		}
		Task struct {
			Value uint8
			Name  string
		}
		Provider struct {
			Guid string
			Name string
		}
		TimeCreated struct {
			SystemTime time.Time
		}
	}
	ExtendedData []string `json:",omitempty"`
}

// So to print the mask in hex mode.
type Keywords struct {
	Mask uint64
	Name []string
}

// Add custom MarshalJSON for Keywords
func (k Keywords) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Mask string   `json:"Mask"`
		Name []string `json:"Name"`
	}{
		Mask: fmt.Sprintf("0x%x", k.Mask),
		Name: k.Name,
	})
}

var (
	eventPool = sync.Pool{
		New: func() interface{} {
			return &Event{
				EventData:    make(map[string]interface{}),
				UserData:     make(map[string]interface{}),
				ExtendedData: make([]string, 0),
			}
		},
	}
)

func NewEvent() *Event {
	return eventPool.Get().(*Event)
}

func (e *Event) reset() {
	// Clear contents
	clear(e.EventData)
	clear(e.UserData)

	// Zero all fields except maps/slices
	*e = Event{
		EventData:    e.EventData,
		UserData:     e.UserData,
		ExtendedData: e.ExtendedData[:0],
	}
}

func (e *Event) Release() {
	e.reset()
	eventPool.Put(e)
}

// TODO(tekert): delete when we are sure we don't need it
func NewEvent_old() (e *Event) {
	e = &Event{}
	e.EventData = make(map[string]interface{})
	e.UserData = make(map[string]interface{})
	e.ExtendedData = make([]string, 0)
	return e
}

func (e *Event) GetProperty(name string) (i interface{}, ok bool) {

	if e.EventData != nil {
		if i, ok = e.EventData[name]; ok {
			return
		}
	}

	if e.UserData != nil {
		if i, ok = e.UserData[name]; ok {
			return
		}
	}

	return
}

func (e *Event) GetPropertyString(name string) (string, bool) {
	if i, ok := e.GetProperty(name); ok {
		if s, ok := i.(string); ok {
			return s, ok
		}
	}
	return "", false
}
