package rule

import (
	"fmt"

	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

const (
	R0005ID                              = "R0005"
	R0005UnexpectedDomainRequestRuleName = "Unexpected domain request"
)

var R0005UnexpectedDomainRequestRuleDescriptor = RuleDesciptor{
	ID:          R0005ID,
	Name:        R0005UnexpectedDomainRequestRuleName,
	Description: "Detecting unexpected domain requests that are not whitelisted by application profile.",
	Tags:        []string{"dns", "whitelisted"},
	Priority:    RulePriorityMed,
	Requirements: RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.DnsEventType},
		NeedApplicationProfile: true,
	},
	RuleCreationFunc: func() Rule {
		return CreateRuleR0005UnexpectedDomainRequest()
	},
}

type R0005UnexpectedDomainRequest struct {
	BaseRule
}

type R0005UnexpectedDomainRequestFailure struct {
	RuleName         string
	RulePriority     int
	FixSuggestionMsg string
	Err              string
	FailureEvent     *tracing.DnsEvent
}

func (rule *R0005UnexpectedDomainRequest) Name() string {
	return R0005UnexpectedDomainRequestRuleName
}

func CreateRuleR0005UnexpectedDomainRequest() *R0005UnexpectedDomainRequest {
	return &R0005UnexpectedDomainRequest{}
}

func (rule *R0005UnexpectedDomainRequest) DeleteRule() {
}

func (rule *R0005UnexpectedDomainRequest) generatePatchCommand(event *tracing.DnsEvent, appProfileAccess approfilecache.SingleApplicationProfileAccess) string {
	baseTemplate := "kubectl patch applicationprofile %s --namespace %s --type merge -p '{\"spec\": {\"containers\": [{\"name\": \"%s\", \"dns\": [{\"dnsName\": \"%s\"}]}]}}'"
	return fmt.Sprintf(baseTemplate, appProfileAccess.GetName(), appProfileAccess.GetNamespace(),
		event.ContainerName, event.DnsName)
}

func (rule *R0005UnexpectedDomainRequest) ProcessEvent(eventType tracing.EventType, event interface{}, appProfileAccess approfilecache.SingleApplicationProfileAccess, engineAccess EngineAccess) RuleFailure {
	if eventType != tracing.DnsEventType {
		return nil
	}

	domainEvent, ok := event.(*tracing.DnsEvent)
	if !ok {
		return nil
	}

	if appProfileAccess == nil {
		return &R0005UnexpectedDomainRequestFailure{
			RuleName:         rule.Name(),
			Err:              "Application profile is missing",
			FixSuggestionMsg: fmt.Sprintf("Create an application profile with the domain %s", domainEvent.DnsName),
			FailureEvent:     domainEvent,
			RulePriority:     R0005UnexpectedDomainRequestRuleDescriptor.Priority,
		}
	}

	appProfileDnsList, err := appProfileAccess.GetDNS()
	if err != nil || appProfileDnsList == nil {
		return &R0005UnexpectedDomainRequestFailure{
			RuleName:         rule.Name(),
			Err:              "Application profile is missing",
			FixSuggestionMsg: fmt.Sprintf("Create an application profile with the domain %s", domainEvent.DnsName),
			FailureEvent:     domainEvent,
			RulePriority:     R0005UnexpectedDomainRequestRuleDescriptor.Priority,
		}
	}

	// Check that the domain is in the application profile
	found := false
	for _, domain := range *appProfileDnsList {
		if domain.DnsName == domainEvent.DnsName {
			found = true
			break
		}
	}

	if !found {
		return &R0005UnexpectedDomainRequestFailure{
			RuleName: rule.Name(),
			Err:      fmt.Sprintf("Unexpected domain request (%s)", domainEvent.DnsName),
			FixSuggestionMsg: fmt.Sprintf("If this is a valid behavior, please add the domain %s to the whitelist in the application profile for the Pod %s. You can use the following command: %s",
				domainEvent.DnsName,
				domainEvent.PodName,
				rule.generatePatchCommand(domainEvent, appProfileAccess)),
			FailureEvent: domainEvent,
			RulePriority: R0005UnexpectedDomainRequestRuleDescriptor.Priority,
		}
	}

	return nil
}

func (rule *R0005UnexpectedDomainRequest) Requirements() RuleRequirements {
	return RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.DnsEventType},
		NeedApplicationProfile: true,
	}
}

func (rule *R0005UnexpectedDomainRequestFailure) Name() string {
	return rule.RuleName
}

func (rule *R0005UnexpectedDomainRequestFailure) Error() string {
	return rule.Err
}

func (rule *R0005UnexpectedDomainRequestFailure) Event() tracing.GeneralEvent {
	return rule.FailureEvent.GeneralEvent
}

func (rule *R0005UnexpectedDomainRequestFailure) Priority() int {
	return rule.RulePriority
}

func (rule *R0005UnexpectedDomainRequestFailure) FixSuggestion() string {
	return rule.FixSuggestionMsg
}
