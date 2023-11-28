package rule

import (
	"fmt"
	"testing"

	"github.com/kubescape/kapprofiler/pkg/tracing"
)

func TestR0003UnexpectedSystemCall(t *testing.T) {
	// Create a new rule
	r := CreateRuleR0003UnexpectedSystemCall()
	// Assert r is not nil
	if r == nil {
		t.Errorf("Expected r to not be nil")
	}

	// Create a syscall event
	e := &tracing.SyscallEvent{
		GeneralEvent: tracing.GeneralEvent{
			ContainerID: "test",
			PodName:     "test",
			Namespace:   "test",
			Timestamp:   0,
		},
		Syscalls: []string{"test"},
	}

	// Test with nil appProfileAccess
	ruleResult := r.ProcessEvent(tracing.SyscallEventType, e, nil, nil)
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to be nil since no syscall event")
	}

	// Test with mock appProfileAccess
	ruleResult = r.ProcessEvent(tracing.SyscallEventType, e, &MockAppProfileAccess{}, nil)
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to be not nil since no syscall event")
	}

	// Test with mock appProfileAccess and syscall
	ruleResult = r.ProcessEvent(tracing.SyscallEventType, e, &MockAppProfileAccess{
		Syscalls: []string{"test"},
	}, nil)
	if ruleResult != nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be nil since syscall is whitelisted")
	}

}
