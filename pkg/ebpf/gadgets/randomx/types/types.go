package types

import (
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type Event struct {
	eventtypes.Event
	eventtypes.WithMountNsID

	Pid  uint32 `json:"pid,omitempty" column:"pid,template:pid"`
	PPid uint32 `json:"ppid,omitempty" column:"ppid,template:ppid"`
	Comm string `json:"comm,omitempty" column:"comm,template:comm"`
	Path string `json:"path,omitempty" column:"path,template:path"`
}

func GetColumns() *columns.Columns[Event] {
	randomxColumns := columns.MustCreateColumns[Event]()

	return randomxColumns
}

func Base(ev eventtypes.Event) *Event {
	return &Event{
		Event: ev,
	}
}
