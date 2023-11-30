package rule

import (
	"fmt"
	"testing"

	"github.com/kubescape/kapprofiler/pkg/tracing"
)

func TestR1002LoadKernelModule(t *testing.T) {
	// Create a new rule
	r := CreateRuleR1002LoadKernelModule()
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
		t.Errorf("Expected ruleResult to be nil since syscall is not init_module")
	}

	// Create a syscall event
	e = &tracing.SyscallEvent{
		GeneralEvent: tracing.GeneralEvent{
			ContainerID: "test",
			PodName:     "test",
			Namespace:   "test",
			Timestamp:   0,
		},
		Syscalls: []string{"init_module"},
	}

	ruleResult = r.ProcessEvent(tracing.SyscallEventType, e, nil, nil)
	if ruleResult == nil {
		fmt.Printf("ruleResult: %v\n", ruleResult)
		t.Errorf("Expected ruleResult to be Failure because of init_module is not allowed")
	}

}
