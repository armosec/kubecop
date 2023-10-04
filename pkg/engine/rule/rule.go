package rule

import "github.com/looplab/fsm"

type IRule interface {
	// Rule Name.
	Name() string
	// Get the rule's state machine.
	GetFSM() *fsm.FSM
}
