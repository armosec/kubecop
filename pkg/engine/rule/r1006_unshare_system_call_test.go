package rule

import (
	"fmt"
	"testing"

	"github.com/kubescape/kapprofiler/pkg/tracing"
)

func TestR1006UnshareSyscall(t *testing.T) {
	// Create a new rule
	r := CreateRuleR1006UnshareSyscall()
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

	ruleResult := r.ProcessEvent(tracing.SyscallEventType, e, nil, nil)
	if ruleResult != nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be nil since syscall is not unshare")
		return
	}

	// Create a syscall event
	e.Syscalls = append(e.Syscalls, "unshare")

	ruleResult = r.ProcessEvent(tracing.SyscallEventType, e, nil, nil)
	if ruleResult == nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be Failure because of unshare is used")
		return
	}

}
