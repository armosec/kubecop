package rule

import (
	"testing"

	"github.com/kubescape/kapprofiler/pkg/tracing"
)

func TestR1003DisallowedSSHConnectionPort_ProcessEvent(t *testing.T) {
	rule := CreateRuleR1003MaliciousSSHConnection()

	// Test case 1: SSH connection to disallowed port
	networkEvent := &tracing.NetworkEvent{
		GeneralEvent: tracing.GeneralEvent{
			ProcessDetails: tracing.ProcessDetails{
				Pid: 1,
			},
			ContainerID: "test",
			PodName:     "test",
			Namespace:   "test",
			Timestamp:   2,
		},
		PacketType:  "OUTGOING",
		Protocol:    "TCP",
		Port:        2222,
		DstEndpoint: "1.1.1.1",
	}

	openEvent := &tracing.OpenEvent{
		GeneralEvent: tracing.GeneralEvent{
			ProcessDetails: tracing.ProcessDetails{
				Pid: 1,
			},
			ContainerID: "test",
			PodName:     "test",
			Namespace:   "test",
			Timestamp:   1,
		},
		PathName: "/etc/ssh/sshd_config",
	}
	rule.ProcessEvent(tracing.OpenEventType, openEvent, nil, &EngineAccessMock{})
	failure := rule.ProcessEvent(tracing.NetworkEventType, networkEvent, nil, &EngineAccessMock{})
	if failure == nil {
		t.Errorf("Expected failure, but got nil")
	}

	// Test case 2: SSH connection to allowed port
	networkEvent.Port = 22
	failure = rule.ProcessEvent(tracing.NetworkEventType, networkEvent, nil, &EngineAccessMock{})
	if failure != nil {
		t.Errorf("Expected failure to be nil, but got %v", failure)
	}

	// Test case 3: SSH connection to disallowed port, but not from SSH initiator
	networkEvent.Port = 2222
	networkEvent.Pid = 2
	failure = rule.ProcessEvent(tracing.NetworkEventType, networkEvent, nil, &EngineAccessMock{})
	if failure != nil {
		t.Errorf("Expected failure to be nil, but got %v", failure)
	}

	// Test case 4: SSH connection to disallowed port, but not from SSH initiator
	networkEvent.Port = 2222
	networkEvent.Pid = 1
	networkEvent.Timestamp = 3
	failure = rule.ProcessEvent(tracing.NetworkEventType, networkEvent, nil, &EngineAccessMock{})
	if failure != nil {
		t.Errorf("Expected failure to be nil, but got %v", failure)
	}

	// Test case 5: Time diff is greater than MaxTimeDiffInSeconds
	networkEvent.Port = 2222
	networkEvent.Pid = 1
	networkEvent.Timestamp = 5
	failure = rule.ProcessEvent(tracing.NetworkEventType, networkEvent, nil, &EngineAccessMock{})
	if failure != nil {
		t.Errorf("Expected failure to be nil, but got %v", failure)
	}
}
