package rule

import (
	"fmt"

	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

const (
	R0004ID                               = "R0004"
	R0004UnexpectedCapabilityUsedRuleName = "Unexpected capability used"
)

var R0004UnexpectedCapabilityUsedRuleDescriptor = RuleDesciptor{
	ID:          R0004ID,
	Name:        R0004UnexpectedCapabilityUsedRuleName,
	Description: "Detecting unexpected capabilities that are not whitelisted by application profile. Every unexpected capability is identified in context of a syscall and will be alerted only once per container.",
	Tags:        []string{"capabilities", "whitelisted"},
	Priority:    RulePriorityHigh,
	Requirements: RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.CapabilitiesEventType},
		NeedApplicationProfile: true,
	},
	RuleCreationFunc: func() Rule {
		return CreateRuleR0004UnexpectedCapabilityUsed()
	},
}

type R0004UnexpectedCapabilityUsed struct {
	BaseRule
}

type R0004UnexpectedCapabilityUsedFailure struct {
	RuleName         string
	RulePriority     int
	Err              string
	FixSuggestionMsg string
	FailureEvent     *tracing.CapabilitiesEvent
}

func (rule *R0004UnexpectedCapabilityUsed) Name() string {
	return R0004UnexpectedCapabilityUsedRuleName
}

func CreateRuleR0004UnexpectedCapabilityUsed() *R0004UnexpectedCapabilityUsed {
	return &R0004UnexpectedCapabilityUsed{}
}

func (rule *R0004UnexpectedCapabilityUsed) DeleteRule() {
}

func (rule *R0004UnexpectedCapabilityUsed) generatePatchCommand(event *tracing.CapabilitiesEvent, appProfileAccess approfilecache.SingleApplicationProfileAccess) string {
	baseTemplate := "kubectl patch applicationprofile %s --namespace %s --type merge -p '{\"spec\": {\"containers\": [{\"name\": \"%s\", \"capabilities\": [{\"syscall\": \"%s\", \"caps\": [%s]}]}]}}'"
	return fmt.Sprintf(baseTemplate, appProfileAccess.GetName(), appProfileAccess.GetNamespace(),
		event.ContainerName, event.Syscall, event.CapabilityName)
}

func (rule *R0004UnexpectedCapabilityUsed) ProcessEvent(eventType tracing.EventType, event interface{}, appProfileAccess approfilecache.SingleApplicationProfileAccess, engineAccess EngineAccess) RuleFailure {
	if eventType != tracing.CapabilitiesEventType {
		return nil
	}

	capEvent, ok := event.(*tracing.CapabilitiesEvent)
	if !ok {
		return nil
	}

	if appProfileAccess == nil {
		return &R0004UnexpectedCapabilityUsedFailure{
			RuleName:         rule.Name(),
			Err:              "Application profile is missing",
			FixSuggestionMsg: fmt.Sprintf("Please create an application profile for the Pod %s", capEvent.PodName),
			FailureEvent:     capEvent,
			RulePriority:     R0004UnexpectedCapabilityUsedRuleDescriptor.Priority,
		}
	}

	appProfileCapabilitiesList, err := appProfileAccess.GetCapabilities()
	if err != nil || appProfileCapabilitiesList == nil {
		return &R0004UnexpectedCapabilityUsedFailure{
			RuleName:         rule.Name(),
			Err:              "Application profile is missing",
			FixSuggestionMsg: fmt.Sprintf("Please create an application profile for the Pod %s", capEvent.PodName),
			FailureEvent:     capEvent,
			RulePriority:     R0004UnexpectedCapabilityUsedRuleDescriptor.Priority,
		}
	}

	found := false
	for _, cap := range *appProfileCapabilitiesList {
		if capEvent.Syscall == cap.Syscall {
			// Check that the capability is in cap.Capabilities
			for _, baselineCapability := range cap.Capabilities {
				if capEvent.CapabilityName == baselineCapability {
					found = true
				}
			}
		}
	}

	if !found {
		return &R0004UnexpectedCapabilityUsedFailure{
			RuleName:         rule.Name(),
			Err:              fmt.Sprintf("Unexpected capability used (capability %s used in syscall %s)", capEvent.CapabilityName, capEvent.Syscall),
			FixSuggestionMsg: fmt.Sprintf("If this is a valid behavior, please add the capability use \"%s\" to the whitelist in the application profile for the Pod \"%s\". You can use the following command: %s", capEvent.CapabilityName, capEvent.PodName, rule.generatePatchCommand(capEvent, appProfileAccess)),
			FailureEvent:     capEvent,
			RulePriority:     R0004UnexpectedCapabilityUsedRuleDescriptor.Priority,
		}
	}

	return nil
}

func (rule *R0004UnexpectedCapabilityUsed) Requirements() RuleRequirements {
	return RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.CapabilitiesEventType},
		NeedApplicationProfile: true,
	}
}

func (rule *R0004UnexpectedCapabilityUsedFailure) Name() string {
	return rule.RuleName
}

func (rule *R0004UnexpectedCapabilityUsedFailure) Error() string {
	return rule.Err
}

func (rule *R0004UnexpectedCapabilityUsedFailure) Event() tracing.GeneralEvent {
	return rule.FailureEvent.GeneralEvent
}

func (rule *R0004UnexpectedCapabilityUsedFailure) Priority() int {
	return rule.RulePriority
}

func (rule *R0004UnexpectedCapabilityUsedFailure) FixSuggestion() string {
	return rule.FixSuggestionMsg
}
