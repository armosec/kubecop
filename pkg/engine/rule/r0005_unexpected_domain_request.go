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
	Priority:    6,
	Requirements: RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.DnsEventType},
		NeedApplicationProfile: true,
	},
	RuleCreationFunc: func() Rule {
		return CreateRuleR0005UnexpectedDomainRequest()
	},
}

type R0005UnexpectedDomainRequest struct {
}

type R0005UnexpectedDomainRequestFailure struct {
	RuleName     string
	RulePriority int
	Err          string
	FailureEvent *tracing.DnsEvent
}

func (rule *R0005UnexpectedDomainRequest) Name() string {
	return R0005UnexpectedDomainRequestRuleName
}

func CreateRuleR0005UnexpectedDomainRequest() *R0005UnexpectedDomainRequest {
	return &R0005UnexpectedDomainRequest{}
}

func (rule *R0005UnexpectedDomainRequest) DeleteRule() {
}

func (rule *R0005UnexpectedDomainRequest) ProcessEvent(eventType tracing.EventType, event interface{}, appProfileAccess approfilecache.SingleApplicationProfileAccess) RuleFailure {
	if eventType != tracing.DnsEventType {
		return nil
	}

	domainEvent, ok := event.(*tracing.DnsEvent)
	if !ok {
		return nil
	}

	if appProfileAccess == nil {
		return &R0005UnexpectedDomainRequestFailure{
			RuleName:     rule.Name(),
			Err:          "Application profile is missing",
			FailureEvent: domainEvent,
			RulePriority: RulePrioritySystemIssue,
		}
	}

	appProfileDnsList, err := appProfileAccess.GetDNS()
	if err != nil || appProfileDnsList == nil {
		return &R0005UnexpectedDomainRequestFailure{
			RuleName:     rule.Name(),
			Err:          "Application profile is missing",
			FailureEvent: domainEvent,
			RulePriority: RulePrioritySystemIssue,
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
			RuleName:     rule.Name(),
			Err:          fmt.Sprintf("Unexpected domain request (%s)", domainEvent.DnsName),
			FailureEvent: domainEvent,
			RulePriority: RulePrioritySystemIssue,
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
