package rule

import (
	"fmt"
	"testing"

	"github.com/kubescape/kapprofiler/pkg/tracing"
)

func TestR1007MemfdCreateSyscall(t *testing.T) {
	// Create a new rule
	r := CreateRuleR1007MemfdCreate()
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
		t.Errorf("Expected ruleResult to be nil since syscall is not memfd_create")
		return
	}

	// Create a syscall event
	e.Syscalls = append(e.Syscalls, "memfd_create")

	ruleResult = r.ProcessEvent(tracing.SyscallEventType, e, nil, nil)
	if ruleResult == nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be Failure because of memfd_create is used")
		return
	}

}
