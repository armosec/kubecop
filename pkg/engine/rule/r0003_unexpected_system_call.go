package rule

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

const (
	R0003ID                           = "R0003"
	R0003UnexpectedSystemCallRuleName = "Unexpected system call"
)

var R0003UnexpectedSystemCallRuleDescriptor = RuleDesciptor{
	ID:          R0003ID,
	Name:        R0003UnexpectedSystemCallRuleName,
	Description: "Detecting unexpected system calls that are not whitelisted by application profile. Every unexpected system call will be alerted only once.",
	Tags:        []string{"syscall", "whitelisted"},
	Priority:    RulePriorityMed,
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
	BaseRule
	listOfAlertedSyscalls []string
}

type R0003UnexpectedSystemCallFailure struct {
	RuleName         string
	RulePriority     int
	Err              string
	FixSuggestionMsg string
	FailureEvent     *tracing.SyscallEvent
}

func (rule *R0003UnexpectedSystemCall) Name() string {
	return R0003UnexpectedSystemCallRuleName
}

func CreateRuleR0003UnexpectedSystemCall() *R0003UnexpectedSystemCall {
	return &R0003UnexpectedSystemCall{}
}

func (rule *R0003UnexpectedSystemCall) DeleteRule() {
}

func (rule *R0003UnexpectedSystemCall) generatePatchCommand(event *tracing.SyscallEvent, unexpectedSyscalls []string, appProfileAccess approfilecache.SingleApplicationProfileAccess) string {
	syscallList, err := json.Marshal(unexpectedSyscalls)
	if err != nil {
		return ""
	}
	baseTemplate := "kubectl patch applicationprofile %s --namespace %s --type merge -p '{\"spec\": {\"containers\": [{\"name\": \"%s\", \"syscalls\": %s}]}}'"
	return fmt.Sprintf(baseTemplate, appProfileAccess.GetName(), appProfileAccess.GetNamespace(),
		event.ContainerName, syscallList)
}

func (rule *R0003UnexpectedSystemCall) ProcessEvent(eventType tracing.EventType, event interface{}, appProfileAccess approfilecache.SingleApplicationProfileAccess, engineAccess EngineAccess) RuleFailure {
	if eventType != tracing.SyscallEventType {
		return nil
	}

	syscallEvent, ok := event.(*tracing.SyscallEvent)
	if !ok {
		return nil
	}

	if appProfileAccess == nil {
		return &R0003UnexpectedSystemCallFailure{
			RuleName:         rule.Name(),
			Err:              "Application profile is missing",
			FixSuggestionMsg: fmt.Sprintf("Please create an application profile for the Pod %s", syscallEvent.PodName),
			FailureEvent:     syscallEvent,
			RulePriority:     R0003UnexpectedSystemCallRuleDescriptor.Priority,
		}
	}

	appProfileSyscallList, err := appProfileAccess.GetSystemCalls()
	if err != nil || appProfileSyscallList == nil {
		return &R0003UnexpectedSystemCallFailure{
			RuleName:         rule.Name(),
			Err:              "Application profile is missing (missing syscall list))",
			FixSuggestionMsg: fmt.Sprintf("Please create an application profile for the Pod %s", syscallEvent.PodName),
			FailureEvent:     syscallEvent,
			RulePriority:     R0003UnexpectedSystemCallRuleDescriptor.Priority,
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
			RuleName:         rule.Name(),
			Err:              "Unexpected system calls: " + strings.Join(unexpectedSyscalls, ", "),
			FixSuggestionMsg: fmt.Sprintf("If this is a valid behavior, please add the system call(s) \"%s\" to the whitelist in the application profile for the Pod \"%s\". You can use the following command: %s", strings.Join(unexpectedSyscalls, ", "), syscallEvent.PodName, rule.generatePatchCommand(syscallEvent, unexpectedSyscalls, appProfileAccess)),
			FailureEvent:     syscallEvent,
			RulePriority:     R0003UnexpectedSystemCallRuleDescriptor.Priority,
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
	return rule.RulePriority
}

func (rule *R0003UnexpectedSystemCallFailure) FixSuggestion() string {
	return rule.FixSuggestionMsg
}
