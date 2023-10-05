package rule

import (
	"context"
	"log"

	"github.com/armosec/kubecop/pkg/ebpf"
	"github.com/looplab/fsm"
)

const (
	ReverseShellRuleName = "ReverseShellRule"
)

// Global variable for the needed events for the rule.
var reverseShellNeededEvents = []ebpf.Event{ebpf.Syscall}

type ReverseShellRule struct {
	fsm      *fsm.FSM
	name     string
	dupCount int // Counter for syscall occurrences
}

func NewReverseShellRule() *ReverseShellRule {
	rule := &ReverseShellRule{
		name:     ReverseShellRuleName,
		dupCount: 0,
	}

	rule.fsm = fsm.NewFSM(
		"start",
		fsm.Events{
			{Name: "syscall", Src: []string{"start", "reset"}, Dst: "dupCount"},
			{Name: "execve", Src: []string{"dupCount"}, Dst: "start"},
			{Name: "reset", Src: []string{"start", "dupCount"}, Dst: "start"},
		},
		fsm.Callbacks{
			"after_syscall": rule.handleSyscall,
			"after_execve":  rule.handleExecve,
		},
	)

	return rule
}

func (rule *ReverseShellRule) handleSyscall(_ context.Context, event *fsm.Event) {
	syscall := event.Args[0].(string)
	if syscall == "dup" || syscall == "dup2" || syscall == "dup3" {
		if rule.dupCount == 3 {
			rule.dupCount = 0
			event.FSM.Event(context.Background(), "reset")
		}
		rule.dupCount++
		event.FSM.Event(context.Background(), "reset")
	} else if rule.dupCount == 3 {
		event.FSM.Event(context.Background(), "execve", syscall)
	} else {
		rule.dupCount = 0
		event.FSM.Event(context.Background(), "reset")
	}
}

func (rule *ReverseShellRule) handleExecve(_ context.Context, event *fsm.Event) {
	syscall := event.Args[0].(string)
	if syscall == "execve" {
		log.Printf("Reverse shell detected!\n")
	}

	rule.dupCount = 0
	event.FSM.Event(context.Background(), "reset")
}

func (rule *ReverseShellRule) Name() string {
	return rule.name
}

func (rule *ReverseShellRule) GetFSM() *fsm.FSM {
	return rule.fsm
}

func (rule *ReverseShellRule) Events() []ebpf.Event {
	return reverseShellNeededEvents
}
