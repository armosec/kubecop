package rule

import (
	"testing"

	"github.com/kubescape/kapprofiler/pkg/tracing"
)

func TestR0008DisallowedSSHConnectionPort_ProcessEvent(t *testing.T) {
	rule := CreateRuleR0008DisallowedSSHConnectionPort()

	// Test case 1: SSH connection to disallowed port
	networkEvent := &tracing.NetworkEvent{
		GeneralEvent: tracing.GeneralEvent{
			ContainerID: "test",
			PodName:     "test",
			Namespace:   "test",
			Timestamp:   2,
			Pid:         1,
		},
		PacketType:  "OUTGOING",
		Protocol:    "TCP",
		Port:        2222,
		DstEndpoint: "1.1.1.1",
	}

	openEvent := &tracing.OpenEvent{
		GeneralEvent: tracing.GeneralEvent{
			ContainerID: "test",
			PodName:     "test",
			Namespace:   "test",
			Pid:         1,
			Timestamp:   1,
		},
		PathName: "/etc/ssh/sshd_config",
	}
	rule.ProcessEvent(tracing.OpenEventType, openEvent, nil)
	failure := rule.ProcessEvent(tracing.NetworkEventType, networkEvent, nil)
	if failure == nil {
		t.Errorf("Expected failure, but got nil")
	}
}
