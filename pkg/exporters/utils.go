package exporters

import "github.com/armosec/kubecop/pkg/engine/rule"

func PriorityToStatus(priority int) string {
	switch priority {
	case rule.RulePriorityNone:
		return "none"
	case rule.RulePriorityLow:
		return "low"
	case rule.RulePriorityMed:
		return "medium"
	case rule.RulePriorityHigh:
		return "high"
	case rule.RulePriorityCritical:
		return "critical"
	case rule.RulePrioritySystemIssue:
		return "system_issue"
	default:
		if priority < rule.RulePriorityMed {
			return "low"
		} else if priority < rule.RulePriorityHigh {
			return "medium"
		} else if priority < rule.RulePriorityCritical {
			return "high"
		}
		return "unknown"
	}
}
