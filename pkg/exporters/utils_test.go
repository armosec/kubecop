package exporters

import (
	"testing"

	"github.com/armosec/kubecop/pkg/engine/rule"
)

func TestPriorityToStatus(t *testing.T) {
	tests := []struct {
		name     string
		priority int
		want     string
	}{
		{
			name:     "none",
			priority: rule.RulePriorityNone,
			want:     "none",
		},
		{
			name:     "low",
			priority: rule.RulePriorityLow,
			want:     "low",
		},
		{
			name:     "medium",
			priority: rule.RulePriorityMed,
			want:     "medium",
		},
		{
			name:     "high",
			priority: rule.RulePriorityHigh,
			want:     "high",
		},
		{
			name:     "critical",
			priority: rule.RulePriorityCritical,
			want:     "critical",
		},
		{
			name:     "system_issue",
			priority: rule.RulePrioritySystemIssue,
			want:     "system_issue",
		},
		{
			name:     "unknown",
			priority: 100,
			want:     "unknown",
		},
		{
			name:     "low2",
			priority: rule.RulePriorityMed - 1,
			want:     "low",
		},
		{
			name:     "medium2",
			priority: rule.RulePriorityHigh - 1,
			want:     "medium",
		},
		{
			name:     "high2",
			priority: rule.RulePriorityCritical - 1,
			want:     "high",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PriorityToStatus(tt.priority); got != tt.want {
				t.Errorf("PriorityToStatus() = %v, want %v", got, tt.want)
			}
		})
	}
}
