package rule

import (
	"slices"

	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

const (
	R1002ID                       = "R1002"
	R1002LoadKernelModuleRuleName = "Kernel Module Load"
)

var R1002LoadKernelModuleRuleDescriptor = RuleDesciptor{
	ID:          R1002ID,
	Name:        R1002LoadKernelModuleRuleName,
	Description: "Detecting Kernel Module Load.",
	Tags:        []string{"syscall", "kernel", "module", "load"},
	Priority:    RulePriorityCritical,
	Requirements: RuleRequirements{
		EventTypes: []tracing.EventType{
			tracing.SyscallEventType,
		},
		NeedApplicationProfile: false,
	},
	RuleCreationFunc: func() Rule {
		return CreateRuleR1002LoadKernelModule()
	},
}

type R1002LoadKernelModule struct {
	BaseRule
}

type R1002LoadKernelModuleFailure struct {
	RuleName         string
	RulePriority     int
	Err              string
	FixSuggestionMsg string
	FailureEvent     *tracing.SyscallEvent
}

func (rule *R1002LoadKernelModule) Name() string {
	return R1002LoadKernelModuleRuleName
}

func CreateRuleR1002LoadKernelModule() *R1002LoadKernelModule {
	return &R1002LoadKernelModule{}
}

func (rule *R1002LoadKernelModule) DeleteRule() {
}

func (rule *R1002LoadKernelModule) ProcessEvent(eventType tracing.EventType, event interface{}, appProfileAccess approfilecache.SingleApplicationProfileAccess, engineAccess EngineAccess) RuleFailure {
	if eventType != tracing.SyscallEventType {
		return nil
	}

	syscallEvent, ok := event.(*tracing.SyscallEvent)
	if !ok {
		return nil
	}
	if slices.Contains(syscallEvent.Syscalls, "init_module") {
		return &R1002LoadKernelModuleFailure{
			RuleName:         rule.Name(),
			Err:              "Kernel Module Load",
			FailureEvent:     syscallEvent,
			FixSuggestionMsg: "If this is a legitimate action, please add consider removing this workload from the binding of this rule",
			RulePriority:     R1002LoadKernelModuleRuleDescriptor.Priority,
		}
	}

	return nil
}

func (rule *R1002LoadKernelModule) Requirements() RuleRequirements {
	return RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.SyscallEventType},
		NeedApplicationProfile: false,
	}
}

func (rule *R1002LoadKernelModuleFailure) Name() string {
	return rule.RuleName
}

func (rule *R1002LoadKernelModuleFailure) Error() string {
	return rule.Err
}

func (rule *R1002LoadKernelModuleFailure) Event() tracing.GeneralEvent {
	return rule.FailureEvent.GeneralEvent
}

func (rule *R1002LoadKernelModuleFailure) Priority() int {
	return rule.RulePriority
}

func (rule *R1002LoadKernelModuleFailure) FixSuggestion() string {
	return rule.FixSuggestionMsg
}
