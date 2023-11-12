package rule

import (
	"testing"
)

// Test CreateRulesByTags
func TestCreateRulesByTags(t *testing.T) {
	// Create a new rule
	rules := CreateRulesByTags([]string{"exec"})
	// Assert r is not nil
	if rules == nil {
		t.Errorf("Expected rules to not be nil")
	}
}

// Test CreateRulesByNames
func TestCreateRulesByNames(t *testing.T) {
	// Create a new rule
	rules := CreateRulesByNames([]string{R0001ExecWhitelistedRuleName})
	// Assert r is not nil
	if rules == nil || len(rules) != 1 {
		t.Errorf("Expected rules to not be nil")
	}
}
