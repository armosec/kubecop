package rule

import (
	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

const (
	RulePriorityNone        = 0
	RulePriorityLow         = 1
	RulePriorityMed         = 5
	RulePriorityHigh        = 8
	RulePriorityCrical      = 10
	RulePrioritySystemIssue = 1000
)

type RuleDesciptor struct {
	// Rule Name.
	Name string
	// Priority.
	Priority int
	// Tags
	Tags []string
	// Rule requirements.
	Requirements RuleRequirements
	// Create a rule function.
	RuleCreationFunc func() Rule
}

type RuleFailure interface {
	// Rule Name.
	Name() string
	// Priority.
	Priority() int
	// Error interface.
	Error() string
	// Generic event
	Event() tracing.GeneralEvent
}

type RuleRequirements struct {
	// Needed events for the rule.
	EventTypes []tracing.EventType

	// Need application profile.
	NeedApplicationProfile bool
}

type Rule interface {
	// Delete a rule instance.
	DeleteRule()

	// Rule Name.
	Name() string

	// Needed events for the rule.
	ProcessEvent(eventType tracing.EventType, event interface{}, appProfileAccess approfilecache.SingleApplicationProfileAccess) RuleFailure

	// Rule requirements.
	Requirements() RuleRequirements
}

func (r *RuleDesciptor) HasTags(tags []string) bool {
	for _, tag := range tags {
		for _, ruleTag := range r.Tags {
			if tag == ruleTag {
				return true
			}
		}
	}
	return false
}
