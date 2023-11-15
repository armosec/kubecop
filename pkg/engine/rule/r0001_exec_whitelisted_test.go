package rule

import (
	"testing"

	"github.com/kubescape/kapprofiler/pkg/collector"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

type MockAppProfileAccess struct {
	Execs    []collector.ExecCalls
	Syscalls []string
}

func (m *MockAppProfileAccess) GetExecList() (*[]collector.ExecCalls, error) {
	return &m.Execs, nil
}

func (m *MockAppProfileAccess) GetOpenList() (*[]collector.OpenCalls, error) {
	return nil, nil
}

func (m *MockAppProfileAccess) GetNetworkActivity() (*collector.NetworkActivity, error) {
	return nil, nil
}

func (m *MockAppProfileAccess) GetSystemCalls() ([]string, error) {
	return m.Syscalls, nil
}

func (m *MockAppProfileAccess) GetCapabilities() ([]collector.CapabilitiesCalls, error) {
	return nil, nil
}

func TestR0001ExecWhitelisted(t *testing.T) {
	// Create a new rule
	r := CreateRuleR0001ExecWhitelisted()
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
	ruleResult := r.ProcessEvent(tracing.ExecveEventType, e, nil)
	if ruleResult == nil {
		t.Errorf("Expected ruleResult to not be nil must have an appProfile")
	}

	// Test with empty appProfileAccess
	ruleResult = r.ProcessEvent(tracing.ExecveEventType, e, &MockAppProfileAccess{})
	if ruleResult == nil {
		t.Errorf("Expected ruleResult since exec is not whitelisted")
	}

	// Test with whitelisted exec
	ruleResult = r.ProcessEvent(tracing.ExecveEventType, e, &MockAppProfileAccess{
		Execs: []collector.ExecCalls{
			{
				Path: "/test",
				Args: []string{"test"},
			},
		},
	})
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since exec is whitelisted")
	}
}
