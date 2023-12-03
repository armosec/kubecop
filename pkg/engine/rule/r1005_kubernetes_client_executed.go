package rule

import (
	"fmt"
	"log"
	"path/filepath"
	"slices"

	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

const (
	R1005ID                               = "R1005"
	R1005KubernetesClientExecutedRuleName = "Kubernetes Client Executed"
)

var KubernetesClients = []string{
	"kubectl",
	"kubeadm",
	"kubelet",
	"kube-proxy",
	"kube-apiserver",
	"kube-controller-manager",
	"kube-scheduler",
	"crictl",
	"docker",
	"containerd",
	"runc",
	"ctr",
	"containerd-shim",
	"containerd-shim-runc-v2",
	"containerd-shim-runc-v1",
	"containerd-shim-runc-v0",
	"containerd-shim-runc",
}

var R1005KubernetesClientExecutedDescriptor = RuleDesciptor{
	ID:          R1005ID,
	Name:        R1005KubernetesClientExecutedRuleName,
	Description: "Detecting exececution of kubernetes client",
	Priority:    RulePriorityCritical,
	Tags:        []string{"exec", "malicious"},
	Requirements: RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.ExecveEventType, tracing.NetworkEventType},
		NeedApplicationProfile: false,
	},
	RuleCreationFunc: func() Rule {
		return CreateRuleR1005KubernetesClientExecuted()
	},
}

type R1005KubernetesClientExecuted struct {
	BaseRule
}

type R1005KubernetesClientExecutedFailure struct {
	RuleName         string
	RulePriority     int
	FixSuggestionMsg string
	Err              string
	FailureEvent     *tracing.GeneralEvent
}

func (rule *R1005KubernetesClientExecuted) Name() string {
	return R1005KubernetesClientExecutedRuleName
}

func CreateRuleR1005KubernetesClientExecuted() *R1005KubernetesClientExecuted {
	return &R1005KubernetesClientExecuted{}
}

func (rule *R1005KubernetesClientExecuted) DeleteRule() {
}

func (rule *R1005KubernetesClientExecuted) handleNetworkEvent(event *tracing.NetworkEvent, engineAccess EngineAccess) *R1005KubernetesClientExecutedFailure {
	apiServerIP, err := engineAccess.GetApiServerIpAddress()
	if apiServerIP == "" || err != nil {
		log.Printf("Failed to get api server ip: %v", err)
		return nil
	}

	if event.DstEndpoint == apiServerIP {
		return &R1005KubernetesClientExecutedFailure{
			RuleName:         rule.Name(),
			Err:              fmt.Sprintf("Kubernetes client executed: %s", event.Comm),
			FixSuggestionMsg: "If this is a legitimate action, please consider removing this workload from the binding of this rule.",
			FailureEvent:     &event.GeneralEvent,
			RulePriority:     R1005KubernetesClientExecutedDescriptor.Priority,
		}
	}

	return nil
}

func (rule *R1005KubernetesClientExecuted) handleExecEvent(event *tracing.ExecveEvent) *R1005KubernetesClientExecutedFailure {
	if slices.Contains(KubernetesClients, filepath.Base(event.PathName)) {
		return &R1005KubernetesClientExecutedFailure{
			RuleName:         rule.Name(),
			Err:              fmt.Sprintf("Kubernetes client executed: %s", event.PathName),
			FixSuggestionMsg: "If this is a legitimate action, please consider removing this workload from the binding of this rule.",
			FailureEvent:     &event.GeneralEvent,
			RulePriority:     R1005KubernetesClientExecutedDescriptor.Priority,
		}
	}

	return nil
}

func (rule *R1005KubernetesClientExecuted) ProcessEvent(eventType tracing.EventType, event interface{}, appProfileAccess approfilecache.SingleApplicationProfileAccess, engineAccess EngineAccess) RuleFailure {
	if eventType != tracing.ExecveEventType && eventType != tracing.NetworkEventType {
		return nil
	}

	if eventType == tracing.ExecveEventType {
		execEvent, ok := event.(*tracing.ExecveEvent)
		if !ok {
			return nil
		}

		result := rule.handleExecEvent(execEvent)
		if result != nil {
			return result
		}

		return nil
	}

	if eventType == tracing.NetworkEventType {
		networkEvent, ok := event.(*tracing.NetworkEvent)
		if !ok {
			return nil
		}

		result := rule.handleNetworkEvent(networkEvent, engineAccess)
		if result != nil {
			return result
		}

		return nil
	}

	return nil
}

func (rule *R1005KubernetesClientExecuted) Requirements() RuleRequirements {
	return RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.ExecveEventType, tracing.NetworkEventType},
		NeedApplicationProfile: false,
	}
}

func (rule *R1005KubernetesClientExecutedFailure) Name() string {
	return rule.RuleName
}

func (rule *R1005KubernetesClientExecutedFailure) Error() string {
	return rule.Err
}

func (rule *R1005KubernetesClientExecutedFailure) Event() tracing.GeneralEvent {
	return *rule.FailureEvent
}

func (rule *R1005KubernetesClientExecutedFailure) Priority() int {
	return rule.RulePriority
}

func (rule *R1005KubernetesClientExecutedFailure) FixSuggestion() string {
	return rule.FixSuggestionMsg
}
