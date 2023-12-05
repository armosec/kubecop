package rule

import (
	"testing"

	"github.com/kubescape/kapprofiler/pkg/collector"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

func TestR0002UnexpectedFileAccess(t *testing.T) {
	// Create a new rule
	r := CreateRuleR0002UnexpectedFileAccess()
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
		PathName: "/test",
		Flags:    []string{"O_RDONLY"},
	}

	// Test with nil appProfileAccess
	ruleResult := r.ProcessEvent(tracing.OpenEventType, e, nil, &EngineAccessMock{})
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to not be nil since no appProfile")
	}

	// Test with empty appProfileAccess
	ruleResult = r.ProcessEvent(tracing.OpenEventType, e, &MockAppProfileAccess{}, &EngineAccessMock{})
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to not be nil since file is not whitelisted")
	}

	// Test with whitelisted file
	ruleResult = r.ProcessEvent(tracing.OpenEventType, e, &MockAppProfileAccess{
		OpenCalls: []collector.OpenCalls{
			{
				Path:  "/test",
				Flags: []string{"O_RDONLY"},
			},
		},
	}, &EngineAccessMock{})
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since file is whitelisted")
	}

	// Test with whitelisted file, but different flags
	e.Flags = []string{"O_WRONLY"}
	ruleResult = r.ProcessEvent(tracing.OpenEventType, e, &MockAppProfileAccess{
		OpenCalls: []collector.OpenCalls{
			{
				Path:  "/test",
				Flags: []string{"O_RDONLY"},
			},
		},
	}, &EngineAccessMock{})
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to not be nil since flag is not whitelisted")
	}

	// Test with mounted file
	e.PathName = "/var/test1"
	r.SetParameters(map[string]interface{}{"ignoreMounts": true})
	ruleResult = r.ProcessEvent(tracing.OpenEventType, e, &MockAppProfileAccess{
		OpenCalls: []collector.OpenCalls{
			{
				Path:  "/test",
				Flags: []string{"O_RDONLY"},
			},
		},
	}, &EngineAccessMock{})

	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since file is mounted")
	}

	// Test with ignored prefix
	e.PathName = "/var/test1"
	ignorePrefixes := []interface{}{"/var"}
	r.SetParameters(map[string]interface{}{"ignoreMounts": false, "ignorePrefixes": ignorePrefixes})
	ruleResult = r.ProcessEvent(tracing.OpenEventType, e, &MockAppProfileAccess{
		OpenCalls: []collector.OpenCalls{
			{
				Path:  "/test",
				Flags: []string{"O_RDONLY"},
			},
		},
	}, &EngineAccessMock{})
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since file is ignored")
	}

}
