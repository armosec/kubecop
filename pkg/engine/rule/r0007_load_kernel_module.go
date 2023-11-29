package rule

import (
	"slices"

	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

const (
	R0007ID                       = "R0007"
	R0007LoadKernelModuleRuleName = "Kernel Module Load"
)

var R0007LoadKernelModuleRuleDescriptor = RuleDesciptor{
	ID:          R0007ID,
	Name:        R0007LoadKernelModuleRuleName,
	Description: "Detecting Kernel Module Load.",
	Tags:        []string{"syscall", "kernel", "module", "load"},
	Priority:    7,
	Requirements: RuleRequirements{
		EventTypes: []tracing.EventType{
			tracing.SyscallEventType,
		},
		NeedApplicationProfile: false,
	},
	RuleCreationFunc: func() Rule {
		return CreateRuleR0007LoadKernelModule()
	},
}

type R0007LoadKernelModule struct {
	BaseRule
}

type R0007LoadKernelModuleFailure struct {
	RuleName         string
	RulePriority     int
	Err              string
	FixSuggestionMsg string
	FailureEvent     *tracing.SyscallEvent
}

func (rule *R0007LoadKernelModule) Name() string {
	return R0007LoadKernelModuleRuleName
}

func CreateRuleR0007LoadKernelModule() *R0007LoadKernelModule {
	return &R0007LoadKernelModule{}
}

func (rule *R0007LoadKernelModule) DeleteRule() {
}

func (rule *R0007LoadKernelModule) ProcessEvent(eventType tracing.EventType, event interface{}, appProfileAccess approfilecache.SingleApplicationProfileAccess, engineAccess EngineAccess) RuleFailure {
	if eventType != tracing.SyscallEventType {
		return nil
	}

	syscallEvent, ok := event.(*tracing.SyscallEvent)
	if !ok {
		return nil
	}
	if slices.Contains(syscallEvent.Syscalls, "init_module") {
		return &R0007LoadKernelModuleFailure{
			RuleName:         rule.Name(),
			Err:              "Kernel Module Load",
			FailureEvent:     syscallEvent,
			FixSuggestionMsg: "If this is a legitimate action, please add consider removing this workload from the binding of this rule",
			RulePriority:     R0007LoadKernelModuleRuleDescriptor.Priority,
		}
	}

	return nil
}

func (rule *R0007LoadKernelModule) Requirements() RuleRequirements {
	return RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.SyscallEventType},
		NeedApplicationProfile: false,
	}
}

func (rule *R0007LoadKernelModuleFailure) Name() string {
	return rule.RuleName
}

func (rule *R0007LoadKernelModuleFailure) Error() string {
	return rule.Err
}

func (rule *R0007LoadKernelModuleFailure) Event() tracing.GeneralEvent {
	return rule.FailureEvent.GeneralEvent
}

func (rule *R0007LoadKernelModuleFailure) Priority() int {
	return rule.RulePriority
}

func (rule *R0007LoadKernelModuleFailure) FixSuggestion() string {
	return rule.FixSuggestionMsg
}
