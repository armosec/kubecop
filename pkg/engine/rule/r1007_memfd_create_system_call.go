package rule

import (
	"slices"

	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

const (
	R1007ID                  = "R1007"
	R1007MemfdCreateRuleName = "memfd_create System Call usage"
)

var R1007MemfdCreateRuleDescriptor = RuleDesciptor{
	ID:          R1007ID,
	Name:        R1007MemfdCreateRuleName,
	Description: "Detecting memfd_create System Call usage, which can used to execute code in memory without creating a file on disk.",
	Tags:        []string{"syscall", "memfd_create", "memory", "malicious"},
	Priority:    RulePriorityHigh,
	Requirements: RuleRequirements{
		EventTypes: []tracing.EventType{
			tracing.SyscallEventType,
		},
		NeedApplicationProfile: false,
	},
	RuleCreationFunc: func() Rule {
		return CreateRuleR1007MemfdCreate()
	},
}

type R1007MemfdCreate struct {
	BaseRule
}

type R1007MemfdCreateFailure struct {
	RuleName         string
	RulePriority     int
	Err              string
	FixSuggestionMsg string
	FailureEvent     *tracing.SyscallEvent
}

func (rule *R1007MemfdCreate) Name() string {
	return R1007MemfdCreateRuleName
}

func CreateRuleR1007MemfdCreate() *R1007MemfdCreate {
	return &R1007MemfdCreate{}
}

func (rule *R1007MemfdCreate) DeleteRule() {
}

func (rule *R1007MemfdCreate) ProcessEvent(eventType tracing.EventType, event interface{}, appProfileAccess approfilecache.SingleApplicationProfileAccess, engineAccess EngineAccess) RuleFailure {
	if eventType != tracing.SyscallEventType {
		return nil
	}

	syscallEvent, ok := event.(*tracing.SyscallEvent)
	if !ok {
		return nil
	}
	if slices.Contains(syscallEvent.Syscalls, "memfd_create") {
		return &R1007MemfdCreateFailure{
			RuleName:         rule.Name(),
			Err:              "memfd_create System Call usage",
			FailureEvent:     syscallEvent,
			FixSuggestionMsg: "If this is a legitimate action, please add consider removing this workload from the binding of this rule",
			RulePriority:     R1007MemfdCreateRuleDescriptor.Priority,
		}
	}

	return nil
}

func (rule *R1007MemfdCreate) Requirements() RuleRequirements {
	return RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.SyscallEventType},
		NeedApplicationProfile: false,
	}
}

func (rule *R1007MemfdCreateFailure) Name() string {
	return rule.RuleName
}

func (rule *R1007MemfdCreateFailure) Error() string {
	return rule.Err
}

func (rule *R1007MemfdCreateFailure) Event() tracing.GeneralEvent {
	return rule.FailureEvent.GeneralEvent
}

func (rule *R1007MemfdCreateFailure) Priority() int {
	return rule.RulePriority
}

func (rule *R1007MemfdCreateFailure) FixSuggestion() string {
	return rule.FixSuggestionMsg
}
