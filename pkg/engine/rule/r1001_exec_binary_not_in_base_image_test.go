package rule

import (
	"testing"

	"github.com/kubescape/kapprofiler/pkg/tracing"
)

func TestR1001ExecBinaryNotInBaseImage(t *testing.T) {
	// Create a new rule
	r := CreateRuleR1001ExecBinaryNotInBaseImage()
	// Assert r is not nil
	if r == nil {
		t.Errorf("Expected r to not be nil")
	}
	// Create a exec event
	e := &tracing.ExecveEvent{
		GeneralEvent: tracing.GeneralEvent{
			ContainerID: "test",
			PodName:     "test",
			Namespace:   "test",
			Timestamp:   0,
		},
		PathName: "/usr/bin/test",
		Args:     []string{"test"},
	}

	// Test with non existing binary
	ruleResult := r.ProcessEvent(tracing.ExecveEventType, e, nil, nil)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since exec is not in the upper layer")
	}
}
