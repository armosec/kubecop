package rule

import (
	"slices"

	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

const (
	R1006ID                     = "R1006"
	R1006UnshareSyscallRuleName = "Unshare System Call usage"
)

var R1006UnshareSyscallRuleDescriptor = RuleDesciptor{
	ID:          R1006ID,
	Name:        R1006UnshareSyscallRuleName,
	Description: "Detecting Unshare System Call usage, which can be used to escape container.",
	Tags:        []string{"syscall", "escape", "unshare"},
	Priority:    RulePriorityHigh,
	Requirements: RuleRequirements{
		EventTypes: []tracing.EventType{
			tracing.SyscallEventType,
		},
		NeedApplicationProfile: false,
	},
	RuleCreationFunc: func() Rule {
		return CreateRuleR1006UnshareSyscall()
	},
}

type R1006UnshareSyscall struct {
	BaseRule
	aleadyNotified bool
}

type R1006UnshareSyscallFailure struct {
	RuleName         string
	RulePriority     int
	Err              string
	FixSuggestionMsg string
	FailureEvent     *tracing.SyscallEvent
}

func (rule *R1006UnshareSyscall) Name() string {
	return R1006UnshareSyscallRuleName
}

func CreateRuleR1006UnshareSyscall() *R1006UnshareSyscall {
	return &R1006UnshareSyscall{aleadyNotified: false}
}

func (rule *R1006UnshareSyscall) DeleteRule() {
}

func (rule *R1006UnshareSyscall) ProcessEvent(eventType tracing.EventType, event interface{}, appProfileAccess approfilecache.SingleApplicationProfileAccess, engineAccess EngineAccess) RuleFailure {
	if rule.aleadyNotified {
		return nil
	}

	if eventType != tracing.SyscallEventType {
		return nil
	}

	syscallEvent, ok := event.(*tracing.SyscallEvent)
	if !ok {
		return nil
	}
	if slices.Contains(syscallEvent.Syscalls, "unshare") {
		rule.aleadyNotified = true
		return &R1006UnshareSyscallFailure{
			RuleName:         rule.Name(),
			Err:              "Unshare System Call usage",
			FailureEvent:     syscallEvent,
			FixSuggestionMsg: "If this is a legitimate action, please add consider removing this workload from the binding of this rule",
			RulePriority:     R1006UnshareSyscallRuleDescriptor.Priority,
		}
	}

	return nil
}

func (rule *R1006UnshareSyscall) Requirements() RuleRequirements {
	return RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.SyscallEventType},
		NeedApplicationProfile: false,
	}
}

func (rule *R1006UnshareSyscallFailure) Name() string {
	return rule.RuleName
}

func (rule *R1006UnshareSyscallFailure) Error() string {
	return rule.Err
}

func (rule *R1006UnshareSyscallFailure) Event() tracing.GeneralEvent {
	return rule.FailureEvent.GeneralEvent
}

func (rule *R1006UnshareSyscallFailure) Priority() int {
	return rule.RulePriority
}

func (rule *R1006UnshareSyscallFailure) FixSuggestion() string {
	return rule.FixSuggestionMsg
}
