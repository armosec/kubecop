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
		return
	}

	event2 := &tracing.ExecveEvent{
		GeneralEvent: tracing.GeneralEvent{
			ContainerID: "test",
			PodName:     "test",
			Namespace:   "test",
			Timestamp:   0,
		},
		PathName: "kubectl",
		Args:     []string{"test"},
	}

	ruleResult = r.ProcessEvent(tracing.ExecveEventType, event2, nil, &EngineAccessMock{})
	if ruleResult == nil {
		t.Errorf("Expected ruleResult since exec is a k8s client")
		return
	}

	event3 := &tracing.ExecveEvent{
		GeneralEvent: tracing.GeneralEvent{
			ContainerID: "test",
			PodName:     "test",
			Namespace:   "test",
			Timestamp:   0,
		},
		PathName: "/a/b/c/kubectl",
		Args:     []string{"test"},
	}

	ruleResult = r.ProcessEvent(tracing.ExecveEventType, event3, nil, &EngineAccessMock{})
	if ruleResult == nil {
		t.Errorf("Expected ruleResult since exec is a k8s client")
		return
	}

	event4 := &tracing.NetworkEvent{
		GeneralEvent: tracing.GeneralEvent{
			ContainerID: "test",
			PodName:     "test",
			Namespace:   "test",
			Timestamp:   0,
		},
		PacketType:  "OUTGOING",
		Protocol:    "TCP",
		Port:        443,
		DstEndpoint: "1.1.1.1",
	}

	ruleResult = r.ProcessEvent(tracing.NetworkEventType, event4, nil, &EngineAccessMock{})
	if ruleResult == nil {
		t.Errorf("Expected ruleResult since network event dst is kube api server")
		return
	}

}
