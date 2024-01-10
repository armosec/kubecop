package rule

import (
	"fmt"
	"path/filepath"
	"slices"

	log "github.com/sirupsen/logrus"

	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

const (
	R0007ID                               = "R0007"
	R0007KubernetesClientExecutedRuleName = "Kubernetes Client Executed"
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

var R0007KubernetesClientExecutedDescriptor = RuleDesciptor{
	ID:          R0007ID,
	Name:        R0007KubernetesClientExecutedRuleName,
	Description: "Detecting exececution of kubernetes client",
	Priority:    RulePriorityCritical,
	Tags:        []string{"exec", "malicious", "whitelisted"},
	Requirements: RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.ExecveEventType, tracing.NetworkEventType},
		NeedApplicationProfile: true,
	},
	RuleCreationFunc: func() Rule {
		return CreateRuleR0007KubernetesClientExecuted()
	},
}

type R0007KubernetesClientExecuted struct {
	BaseRule
}

type R0007KubernetesClientExecutedFailure struct {
	RuleName         string
	RulePriority     int
	FixSuggestionMsg string
	Err              string
	FailureEvent     *tracing.GeneralEvent
}

func (rule *R0007KubernetesClientExecuted) Name() string {
	return R0007KubernetesClientExecutedRuleName
}

func CreateRuleR0007KubernetesClientExecuted() *R0007KubernetesClientExecuted {
	return &R0007KubernetesClientExecuted{}
}

func (rule *R0007KubernetesClientExecuted) DeleteRule() {
}

func (rule *R0007KubernetesClientExecuted) handleNetworkEvent(event *tracing.NetworkEvent, appProfileAccess approfilecache.SingleApplicationProfileAccess, engineAccess EngineAccess) *R0007KubernetesClientExecutedFailure {
	whitelistedNetworks, err := appProfileAccess.GetNetworkActivity()
	if err != nil {
		log.Printf("Failed to get network list from app profile: %v", err)
		return nil
	}

	for _, whitelistedNetwork := range whitelistedNetworks.Outgoing {
		if whitelistedNetwork.DstEndpoint == event.DstEndpoint {
			return nil
		}
	}

	apiServerIP, err := engineAccess.GetApiServerIpAddress()
	if apiServerIP == "" || err != nil {
		log.Printf("Failed to get api server ip: %v", err)
		return nil
	}

	if event.DstEndpoint == apiServerIP {
		return &R0007KubernetesClientExecutedFailure{
			RuleName:         rule.Name(),
			Err:              fmt.Sprintf("Kubernetes client executed: %s", event.Comm),
			FixSuggestionMsg: "If this is a legitimate action, please consider removing this workload from the binding of this rule.",
			FailureEvent:     &event.GeneralEvent,
			RulePriority:     R0007KubernetesClientExecutedDescriptor.Priority,
		}
	}

	return nil
}

func (rule *R0007KubernetesClientExecuted) handleExecEvent(event *tracing.ExecveEvent, appProfileAccess approfilecache.SingleApplicationProfileAccess) *R0007KubernetesClientExecutedFailure {
	whitelistedExecs, err := appProfileAccess.GetExecList()
	if err != nil {
		log.Printf("Failed to get exec list from app profile: %v", err)
		return nil
	}

	for _, whitelistedExec := range *whitelistedExecs {
		if whitelistedExec.Path == event.PathName {
			return nil
		}
	}

	if slices.Contains(KubernetesClients, filepath.Base(event.PathName)) {
		return &R0007KubernetesClientExecutedFailure{
			RuleName:         rule.Name(),
			Err:              fmt.Sprintf("Kubernetes client executed: %s", event.PathName),
			FixSuggestionMsg: "If this is a legitimate action, please consider removing this workload from the binding of this rule.",
			FailureEvent:     &event.GeneralEvent,
			RulePriority:     R0007KubernetesClientExecutedDescriptor.Priority,
		}
	}

	return nil
}

func (rule *R0007KubernetesClientExecuted) ProcessEvent(eventType tracing.EventType, event interface{}, appProfileAccess approfilecache.SingleApplicationProfileAccess, engineAccess EngineAccess) RuleFailure {
	if eventType != tracing.ExecveEventType && eventType != tracing.NetworkEventType {
		return nil
	}

	if eventType == tracing.ExecveEventType {
		execEvent, ok := event.(*tracing.ExecveEvent)
		if !ok {
			return nil
		}

		result := rule.handleExecEvent(execEvent, appProfileAccess)
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

		if networkEvent.PacketType != "OUTGOING" {
			return nil
		}

		result := rule.handleNetworkEvent(networkEvent, appProfileAccess, engineAccess)
		if result != nil {
			return result
		}

		return nil
	}

	return nil
}

func (rule *R0007KubernetesClientExecuted) Requirements() RuleRequirements {
	return RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.ExecveEventType, tracing.NetworkEventType},
		NeedApplicationProfile: true,
	}
}

func (rule *R0007KubernetesClientExecutedFailure) Name() string {
	return rule.RuleName
}

func (rule *R0007KubernetesClientExecutedFailure) Error() string {
	return rule.Err
}

func (rule *R0007KubernetesClientExecutedFailure) Event() tracing.GeneralEvent {
	return *rule.FailureEvent
}

func (rule *R0007KubernetesClientExecutedFailure) Priority() int {
	return rule.RulePriority
}

func (rule *R0007KubernetesClientExecutedFailure) FixSuggestion() string {
	return rule.FixSuggestionMsg
}
