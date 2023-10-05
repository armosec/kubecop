package rule

import (
	"context"
	"log"

	"github.com/armosec/kubecop/pkg/ebpf"
	"github.com/looplab/fsm"
)

const (
	NonWhitelistedExecRuleName = "NonWhitelistedExecRule"
)

// Global variable for the needed events for the rule.
var execNeededEvents = []ebpf.Event{ebpf.Exec}

type NonWhitelistedExecRule struct {
	fsm              *fsm.FSM
	name             string
	whitelistedExecs []string // TODO: get whitelisted execs from DB/CRD.
}

func NewNonWhitelistedExecRule() *NonWhitelistedExecRule {
	rule := &NonWhitelistedExecRule{
		name:             NonWhitelistedExecRuleName,
		whitelistedExecs: []string{"ls", "cat", "echo"}, // TODO: get whitelisted execs from DB/CRD.
	}

	// TODO: Remove the whitelist/non-whitelist events and use only the exec event.
	// The current implementation is just a placeholder to demonstrate the usage of the FSM.
	rule.fsm = fsm.NewFSM(
		"start",
		fsm.Events{
			{Name: "exec", Src: []string{"start"}, Dst: "exec"},
			{Name: "whitelisted", Src: []string{"exec"}, Dst: "start"},
			{Name: "non-whitelisted", Src: []string{"exec"}, Dst: "start"},
		},
		fsm.Callbacks{
			"after_exec":            rule.handleExec,
			"after_whitelisted":     rule.handleWhitelisted,
			"after_non-whitelisted": rule.handleNonWhitelisted,
		},
	)

	return rule
}

func (rule *NonWhitelistedExecRule) handleExec(_ context.Context, event *fsm.Event) {
	exec := event.Args[0].(string)
	log.Printf("exec %v is being executed\n", exec)
	if rule.isWhitelisted(exec) {
		event.FSM.Event(context.Background(), "whitelisted", exec)
	} else {
		event.FSM.Event(context.Background(), "non-whitelisted", exec)
	}
}

func (rule *NonWhitelistedExecRule) handleWhitelisted(_ context.Context, event *fsm.Event) {
	exec := event.Args[0].(string)
	log.Printf("exec %v is whitelisted\n", exec)
}

func (rule *NonWhitelistedExecRule) handleNonWhitelisted(_ context.Context, event *fsm.Event) {
	exec := event.Args[0].(string)
	log.Printf("exec %v is not whitelisted\n", exec)
}

func (rule *NonWhitelistedExecRule) isWhitelisted(exec string) bool {
	for _, whitelistedExec := range rule.whitelistedExecs {
		if whitelistedExec == exec {
			return true
		}
	}

	return false
}

func (rule *NonWhitelistedExecRule) Name() string {
	return rule.name
}

func (rule *NonWhitelistedExecRule) GetFSM() *fsm.FSM {
	return rule.fsm
}

func (rule *NonWhitelistedExecRule) Events() []ebpf.Event {
	return execNeededEvents
}
