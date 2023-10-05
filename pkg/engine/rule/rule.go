package rule

import (
	"github.com/armosec/kubecop/pkg/ebpf"
	"github.com/looplab/fsm"
)

type IRule interface {
	// Rule Name.
	Name() string
	// Get the rule's state machine.
	GetFSM() *fsm.FSM
	// Needed events for the rule.
	Events() []ebpf.Event
}
