package rule

import (
	"testing"

	"github.com/kubescape/kapprofiler/pkg/tracing"
)

func TestR1005KubernetesClientExecuted(t *testing.T) {
	// Create a new rule
	r := CreateRuleR1005KubernetesClientExecuted()
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

	ruleResult := r.ProcessEvent(tracing.ExecveEventType, e, nil, &EngineAccessMock{})
	if ruleResult != nil {
		t.Errorf("Expected ruleResult to be nil since test is not a k8s client")
	}

	e.PathName = "kubectl"

	ruleResult = r.ProcessEvent(tracing.ExecveEventType, e, nil, &EngineAccessMock{})
	if ruleResult == nil {
		t.Errorf("Expected ruleResult since exec is a k8s client")
	}

	e.PathName = "/a/b/c/kubectl"

	ruleResult = r.ProcessEvent(tracing.ExecveEventType, e, nil, &EngineAccessMock{})
	if ruleResult == nil {
		t.Errorf("Expected ruleResult since exec is a k8s client")
	}
}
