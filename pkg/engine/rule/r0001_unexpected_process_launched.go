package rule

import (
	"fmt"

	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

const (
	R0001ID                                = "R0001"
	R0001UnexpectedProcessLaunchedRuleName = "Unexpected process launched"
)

var R0001UnexpectedProcessLaunchedRuleDescriptor = RuleDesciptor{
	ID:          R0001ID,
	Name:        R0001UnexpectedProcessLaunchedRuleName,
	Description: "Detecting exec calls that are not whitelisted by application profile",
	Tags:        []string{"exec", "whitelisted"},
	Priority:    RulePriorityCritical,
	Requirements: RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.ExecveEventType},
		NeedApplicationProfile: true,
	},
	RuleCreationFunc: func() Rule {
		return CreateRuleR0001UnexpectedProcessLaunched()
	},
}

type R0001UnexpectedProcessLaunched struct {
	BaseRule
}

type R0001UnexpectedProcessLaunchedFailure struct {
	RuleName         string
	Err              string
	RulePriority     int
	FixSuggestionMsg string
	FailureEvent     *tracing.ExecveEvent
}

func (rule *R0001UnexpectedProcessLaunched) Name() string {
	return R0001UnexpectedProcessLaunchedRuleName
}

func CreateRuleR0001UnexpectedProcessLaunched() *R0001UnexpectedProcessLaunched {
	return &R0001UnexpectedProcessLaunched{}
}

func (rule *R0001UnexpectedProcessLaunched) DeleteRule() {
}

func (rule *R0001UnexpectedProcessLaunched) generatePatchCommand(event *tracing.ExecveEvent, appProfileAccess approfilecache.SingleApplicationProfileAccess) string {
	argList := "["
	for _, arg := range event.Args {
		argList += "\"" + arg + "\","
	}
	// remove the last comma
	if len(argList) > 1 {
		argList = argList[:len(argList)-1]
	}
	argList += "]"
	baseTemplate := "kubectl patch applicationprofile %s --namespace %s --type merge -p '{\"spec\": {\"containers\": [{\"name\": \"%s\", \"execs\": [{\"path\": \"%s\", \"args\": %s}]}]}}'"
	return fmt.Sprintf(baseTemplate, appProfileAccess.GetName(), appProfileAccess.GetNamespace(),
		event.ContainerName, event.PathName, argList)
}

func (rule *R0001UnexpectedProcessLaunched) ProcessEvent(eventType tracing.EventType, event interface{}, appProfileAccess approfilecache.SingleApplicationProfileAccess, engineAccess EngineAccess) RuleFailure {
	if eventType != tracing.ExecveEventType {
		return nil
	}

	execEvent, ok := event.(*tracing.ExecveEvent)
	if !ok {
		return nil
	}

	if appProfileAccess == nil {
		return &R0001UnexpectedProcessLaunchedFailure{
			RuleName:         rule.Name(),
			Err:              "Application profile is missing",
			FailureEvent:     execEvent,
			FixSuggestionMsg: fmt.Sprintf("Please create an application profile for the Pod \"%s\" and add the exec call \"%s\" to the whitelist", execEvent.PodName, execEvent.PathName),
			RulePriority:     R0001UnexpectedProcessLaunchedRuleDescriptor.Priority,
		}
	}

	appProfileExecList, err := appProfileAccess.GetExecList()
	if err != nil || appProfileExecList == nil {
		return &R0001UnexpectedProcessLaunchedFailure{
			RuleName:         rule.Name(),
			Err:              "Application profile is missing",
			FailureEvent:     execEvent,
			FixSuggestionMsg: fmt.Sprintf("Please create an application profile for the Pod \"%s\" and add the exec call \"%s\" to the whitelist", execEvent.PodName, execEvent.PathName),
			RulePriority:     R0001UnexpectedProcessLaunchedRuleDescriptor.Priority,
		}
	}

	for _, execCall := range *appProfileExecList {
		if execCall.Path == execEvent.PathName {
			return nil
		}
	}

	return &R0001UnexpectedProcessLaunchedFailure{
		RuleName:         rule.Name(),
		Err:              fmt.Sprintf("exec call \"%s\" is not whitelisted by application profile", execEvent.PathName),
		FailureEvent:     execEvent,
		FixSuggestionMsg: fmt.Sprintf("If this is a valid behavior, please add the exec call \"%s\" to the whitelist in the application profile for the Pod \"%s\". You can use the following command: %s", execEvent.PathName, execEvent.PodName, rule.generatePatchCommand(execEvent, appProfileAccess)),
		RulePriority:     R0001UnexpectedProcessLaunchedRuleDescriptor.Priority,
	}
}

func (rule *R0001UnexpectedProcessLaunched) Requirements() RuleRequirements {
	return RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.ExecveEventType},
		NeedApplicationProfile: true,
	}
}

func (rule *R0001UnexpectedProcessLaunchedFailure) Name() string {
	return rule.RuleName
}

func (rule *R0001UnexpectedProcessLaunchedFailure) Error() string {
	return rule.Err
}

func (rule *R0001UnexpectedProcessLaunchedFailure) Event() tracing.GeneralEvent {
	return rule.FailureEvent.GeneralEvent
}

func (rule *R0001UnexpectedProcessLaunchedFailure) Priority() int {
	return rule.RulePriority
}

func (rule *R0001UnexpectedProcessLaunchedFailure) FixSuggestion() string {
	return rule.FixSuggestionMsg
}
