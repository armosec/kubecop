package rule

import (
	"testing"

	"github.com/kubescape/kapprofiler/pkg/collector"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

func TestR0001UnexpectedProcessLaunched(t *testing.T) {
	// Create a new rule
	r := CreateRuleR0001UnexpectedProcessLaunched()
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
		PathName: "/test",
		Args:     []string{"test"},
	}

	// Test with nil appProfileAccess
	ruleResult := r.ProcessEvent(tracing.ExecveEventType, e, nil, nil)
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to not be nil must have an appProfile")
	}

	// Test with empty appProfileAccess
	ruleResult = r.ProcessEvent(tracing.ExecveEventType, e, &MockAppProfileAccess{}, nil)
	if ruleResult == nil {
		t.Errorf("Expected ruleResult since exec is not whitelisted")
	}

	if ruleResult.FixSuggestion() == "" {
		t.Errorf("Expected fix suggestion to not be empty")
	}

	// Test with whitelisted exec
	ruleResult = r.ProcessEvent(tracing.ExecveEventType, e, &MockAppProfileAccess{
		Execs: []collector.ExecCalls{
			{
				Path: "/test",
				Args: []string{"test"},
			},
		},
	}, nil)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since exec is whitelisted")
	}
}
