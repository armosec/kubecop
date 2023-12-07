package rule

import (
	"sync"

	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

const (
	RulePriorityNone        = 0
	RulePriorityLow         = 1
	RulePriorityMed         = 5
	RulePriorityHigh        = 8
	RulePriorityCritical    = 10
	RulePrioritySystemIssue = 1000
)

type RuleDesciptor struct {
	// Rule ID
	ID string
	// Rule Name.
	Name string
	// Rule Description.
	Description string
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
	// Fix suggestion.
	FixSuggestion() string
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
	ProcessEvent(eventType tracing.EventType, event interface{}, appProfileAccess approfilecache.SingleApplicationProfileAccess, engineAccess EngineAccess) RuleFailure

	// Rule requirements.
	Requirements() RuleRequirements

	// Set rule parameters.
	SetParameters(parameters map[string]interface{})

	// Get rule parameters.
	GetParameters() map[string]interface{}
}

type BaseRule struct {
	// Mutex for protecting rule parameters.
	parametersMutex sync.RWMutex
	parameters      map[string]interface{}
}

func (rule *BaseRule) SetParameters(parameters map[string]interface{}) {
	rule.parametersMutex.Lock()
	defer rule.parametersMutex.Unlock()
	rule.parameters = parameters
}

func (rule *BaseRule) GetParameters() map[string]interface{} {
	rule.parametersMutex.RLock()
	defer rule.parametersMutex.RUnlock()
	if rule.parameters == nil {
		rule.parameters = make(map[string]interface{})
		return rule.parameters
	}

	// Create a copy to avoid returning a reference to the internal map
	parametersCopy := make(map[string]interface{})
	for key, value := range rule.parameters {
		parametersCopy[key] = value
	}

	return parametersCopy
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
