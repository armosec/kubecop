package rule

import (
	"strings"

	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

const (
	R0003UnexpectedSystemCallRuleName = "R0003 Unexpected system call"
)

var R0003UnexpectedSystemCallRuleDescriptor = RuleDesciptor{
	Name:     R0003UnexpectedSystemCallRuleName,
	Tags:     []string{"syscall", "whitelisted"},
	Priority: 7,
	Requirements: RuleRequirements{
		EventTypes: []tracing.EventType{
			tracing.SyscallEventType,
		},
		NeedApplicationProfile: true,
	},
	RuleCreationFunc: func() Rule {
		return CreateRuleR0003UnexpectedSystemCall()
	},
}

type R0003UnexpectedSystemCall struct {
	listOfAlertedSyscalls []string
}

type R0003UnexpectedSystemCallFailure struct {
	RuleName     string
	Err          string
	FailureEvent *tracing.SyscallEvent
}

func (rule *R0003UnexpectedSystemCall) Name() string {
	return R0003UnexpectedSystemCallRuleName
}

func CreateRuleR0003UnexpectedSystemCall() *R0003UnexpectedSystemCall {
	return &R0003UnexpectedSystemCall{}
}

func (rule *R0003UnexpectedSystemCall) DeleteRule() {
}

func (rule *R0003UnexpectedSystemCall) ProcessEvent(eventType tracing.EventType, event interface{}, appProfileAccess approfilecache.SingleApplicationProfileAccess) RuleFailure {
	if eventType != tracing.SyscallEventType {
		return nil
	}

	syscallEvent, ok := event.(*tracing.SyscallEvent)
	if !ok {
		return nil
	}

	if appProfileAccess == nil {
		return &R0003UnexpectedSystemCallFailure{
			RuleName:     rule.Name(),
			Err:          "Application profile is missing",
			FailureEvent: syscallEvent,
		}
	}

	appProfileSyscallList, err := appProfileAccess.GetSystemCalls()
	if err != nil || appProfileSyscallList == nil {
		return &R0003UnexpectedSystemCallFailure{
			RuleName:     rule.Name(),
			Err:          "Application profile is missing (missing syscall list))",
			FailureEvent: syscallEvent,
		}
	}

	unexpectedSyscalls := []string{}
	for _, syscallEventName := range syscallEvent.Syscalls {
		// Check in the appProfileSyscallList if the syscallEventName is there
		found := false
		for _, syscall := range appProfileSyscallList {
			if syscall == syscallEventName {
				found = true
				break
			}
		}
		if !found {
			// Check if the syscallEventName is already in the listOfAlertedSyscalls
			found = false
			for _, alertedSyscall := range rule.listOfAlertedSyscalls {
				if alertedSyscall == syscallEventName {
					found = true
					break
				}
			}
			if !found {
				unexpectedSyscalls = append(unexpectedSyscalls, syscallEventName)
				rule.listOfAlertedSyscalls = append(rule.listOfAlertedSyscalls, syscallEventName)
			}
		}
	}

	if len(unexpectedSyscalls) > 0 {
		return &R0003UnexpectedSystemCallFailure{
			RuleName:     rule.Name(),
			Err:          "Unexpected system calls: " + strings.Join(unexpectedSyscalls, ", "),
			FailureEvent: syscallEvent,
		}
	}

	return nil
}

func (rule *R0003UnexpectedSystemCall) Requirements() RuleRequirements {
	return RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.SyscallEventType},
		NeedApplicationProfile: true,
	}
}

func (rule *R0003UnexpectedSystemCallFailure) Name() string {
	return rule.RuleName
}

func (rule *R0003UnexpectedSystemCallFailure) Error() string {
	return rule.Err
}

func (rule *R0003UnexpectedSystemCallFailure) Event() tracing.GeneralEvent {
	return rule.FailureEvent.GeneralEvent
}

func (rule *R0003UnexpectedSystemCallFailure) Priority() int {
	return R0003UnexpectedSystemCallRuleDescriptor.Priority
}
