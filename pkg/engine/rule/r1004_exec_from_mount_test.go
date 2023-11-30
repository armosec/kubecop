package rule

import (
	"testing"

	"github.com/kubescape/kapprofiler/pkg/tracing"
)

func TestR1004ExecFromMount(t *testing.T) {
	// Create a new rule
	r := CreateRuleR1004ExecFromMount()
	// Assert r is not nil
	if r == nil {
		t.Errorf("Expected r to not be nil")
	}
	// Create a exec event
	e := &tracing.ExecveEvent{
		GeneralEvent: tracing.GeneralEvent{
			ContainerID:   "test",
			ContainerName: "test",
			PodName:       "test",
			Namespace:     "test",
			Timestamp:     0,
		},
		PathName: "/test",
		Args:     []string{"test"},
	}

	// Test case where path is not mounted
	ruleResult := r.ProcessEvent(tracing.ExecveEventType, e, nil, &EngineAccessMock{})
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since test is not from a mounted path")
	}

	// Test case where path is mounted

	e.PathName = "/var/test1/test"

	ruleResult = r.ProcessEvent(tracing.ExecveEventType, e, nil, &EngineAccessMock{})
	if ruleResult == nil {
		t.Errorf("Expected ruleResult since exec is from a mounted path")
	}
}
