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
	Priority:    9,
	Tags:        []string{"exec", "malicious"},
	Requirements: RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.ExecveEventType},
		NeedApplicationProfile: false,
	},
	RuleCreationFunc: func() Rule {
		return CreateRuleR1005KubernetesClientExecution()
	},
}

type R1005KubernetesClientExecuted struct {
}

type R1005KubernetesClientExecutedFailure struct {
	RuleName         string
	RulePriority     int
	FixSuggestionMsg string
	Err              string
	FailureEvent     *tracing.ExecveEvent
}

func (rule *R1005KubernetesClientExecuted) Name() string {
	return R1005KubernetesClientExecutedRuleName
}

func CreateRuleR1005KubernetesClientExecuted() *R1005KubernetesClientExecuted {
	return &R1005KubernetesClientExecuted{}
}

func (rule *R1005KubernetesClientExecuted) DeleteRule() {
}

func (rule *R1005KubernetesClientExecuted) ProcessEvent(eventType tracing.EventType, event interface{}, appProfileAccess approfilecache.SingleApplicationProfileAccess, engineAccess EngineAccess) RuleFailure {
	if eventType != tracing.ExecveEventType {
		return nil
	}

	execEvent, ok := event.(*tracing.ExecveEvent)
	if !ok {
		return nil
	}

	if slices.Contains(KubernetesClients, filepath.Base(execEvent.PathName)) {
		log.Printf("Kubernetes client executed: %s", filepath.Base(execEvent.PathName))
		return &R1005KubernetesClientExecutedFailure{
			RuleName:         rule.Name(),
			Err:              fmt.Sprintf("Kubernetes client executed: %s", execEvent.PathName),
			FixSuggestionMsg: "If this is a legitimate action, please consider removing this workload from the binding of this rule.",
			FailureEvent:     execEvent,
			RulePriority:     R1005KubernetesClientExecutedDescriptor.Priority,
		}
	}

	return nil
}

func (rule *R1005KubernetesClientExecuted) Requirements() RuleRequirements {
	return RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.ExecveEventType},
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
	return rule.FailureEvent.GeneralEvent
}

func (rule *R1005KubernetesClientExecutedFailure) Priority() int {
	return rule.RulePriority
}

func (rule *R1005KubernetesClientExecutedFailure) FixSuggestion() string {
	return rule.FixSuggestionMsg
}
