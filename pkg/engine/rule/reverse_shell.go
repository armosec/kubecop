package rule

import (
	"context"
	"log"

	"github.com/looplab/fsm"
)

const (
	ReverseShellRuleName = "ReverseShellRule"
)

type ReverseShellRule struct {
	fsm  *fsm.FSM
	name string
}

// TODO: implement the reverse shell rule. The current implementation is just a placeholder.

func NewReverseShellRule() *ReverseShellRule {
	rule := &ReverseShellRule{
		name: ReverseShellRuleName,
	}

	rule.fsm = fsm.NewFSM(
		"start",
		fsm.Events{
			{Name: "syscall", Src: []string{"start"}, Dst: "reset"},
			{Name: "execve", Src: []string{"syscall"}, Dst: "done"},
			{Name: "reset", Src: []string{"done"}, Dst: "start"},
		},
		fsm.Callbacks{
			"enter_syscall": rule.handleSyscall,
			"after_execve":  rule.handleExecve,
		},
	)

	return rule
}

func (rule *ReverseShellRule) handleSyscall(_ context.Context, event *fsm.Event) {
	syscall := event.Args[0].(string)
	log.Printf("syscall %v is being executed\n", syscall)
	if syscall == "dup" {
		event.FSM.Event(context.Background(), "execve", syscall)
	} else if syscall == "dup2" {
		event.FSM.Event(context.Background(), "execve", syscall)
	} else if syscall == "dup3" {
		event.FSM.Event(context.Background(), "execve", syscall)
	} else {
		event.FSM.Event(context.Background(), "reset", syscall)
	}
}

func (rule *ReverseShellRule) handleExecve(_ context.Context, event *fsm.Event) {
	syscall := event.Args[0].(string)
	log.Printf("syscall %v is being executed\n", syscall)
	if syscall == "execve" && event.Src == "syscall" {
		log.Printf("Reverse shell detected!\n")
	}

	event.FSM.Event(context.Background(), "reset", syscall)
}
