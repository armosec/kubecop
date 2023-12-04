package rule

import (
	"testing"

	"github.com/kubescape/kapprofiler/pkg/collector"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

func TestR0006UnexpectedServiceAccountTokenMount(t *testing.T) {
	// Create a new rule
	r := CreateRuleR0006UnexpectedServiceAccountTokenAccess()
	// Assert r is not nil
	if r == nil {
		t.Errorf("Expected r to not be nil")
	}

	// Create a file access event
	e := &tracing.OpenEvent{
		GeneralEvent: tracing.GeneralEvent{
			ContainerID:   "test",
			PodName:       "test",
			Namespace:     "test",
			ContainerName: "test",
			Timestamp:     0,
		},
		PathName: "/run/secrets/kubernetes.io/serviceaccount",
		Flags:    []string{"O_RDONLY"},
	}

	// Test with nil appProfileAccess
	ruleResult := r.ProcessEvent(tracing.OpenEventType, e, nil, &EngineAccessMock{})
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to not be nil since no appProfile")
		return
	}

	// Test with empty appProfileAccess
	ruleResult = r.ProcessEvent(tracing.OpenEventType, e, &MockAppProfileAccess{}, &EngineAccessMock{})
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to not be nil since file is not whitelisted")
		return
	}

	// Test with whitelisted file
	e.PathName = "/run/secrets/kubernetes.io/serviceaccount/asdasd"
	ruleResult = r.ProcessEvent(tracing.OpenEventType, e, &MockAppProfileAccess{
		OpenCalls: []collector.OpenCalls{
			{
				Path:  "/var/run/secrets/kubernetes.io/serviceaccount",
				Flags: []string{"O_RDONLY"},
			},
		},
	}, &EngineAccessMock{})
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since file is whitelisted")
	}
}
