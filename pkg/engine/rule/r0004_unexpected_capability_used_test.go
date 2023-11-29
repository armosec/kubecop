package rule

import (
	"testing"

	"github.com/kubescape/kapprofiler/pkg/collector"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

func TestR0004UnexpectedCapabilityUsed(t *testing.T) {
	// Create a new rule
	r := CreateRuleR0004UnexpectedCapabilityUsed()
	// Assert r is not nil
	if r == nil {
		t.Errorf("Expected r to not be nil")
	}

	// Create a capability event
	e := &tracing.CapabilitiesEvent{
		GeneralEvent: tracing.GeneralEvent{
			ContainerID: "test",
			PodName:     "test",
			Namespace:   "test",
			Timestamp:   0,
		},
		CapabilityName: "test_cap",
		Syscall:        "test_call",
	}

	// Test with nil appProfileAccess
	ruleResult := r.ProcessEvent(tracing.CapabilitiesEventType, e, nil, nil)
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to be nil since no capability event")
	}

	// Test with mock appProfileAccess
	ruleResult = r.ProcessEvent(tracing.CapabilitiesEventType, e, &MockAppProfileAccess{
		Capabilities: []collector.CapabilitiesCalls{
			{
				Capabilities: []string{"test_cap"},
				Syscall:      "test_call",
			},
		},
	}, nil)
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since capability is in the profile")
	}
}
