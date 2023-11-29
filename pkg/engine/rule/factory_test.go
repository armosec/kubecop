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
	rules := CreateRulesByNames([]string{R0001UnexpectedProcessLaunchedRuleName})
	// Assert r is not nil
	if rules == nil || len(rules) != 1 {
		t.Errorf("Expected rules to not be nil")
	}
}

// Test CreateRuleByName
func TestCreateRuleByName(t *testing.T) {
	// Create a new rule
	rule := CreateRuleByName(R0001UnexpectedProcessLaunchedRuleName)
	// Assert r is not nil
	if rule == nil {
		t.Errorf("Expected rule to not be nil")
	}
	// not exist
	rule = CreateRuleByName("not exist")
	// Assert r is not nil
	if rule != nil {
		t.Errorf("Expected rule to be nil")
	}
}

// Test CreateRuleByID
func TestCreateRuleByID(t *testing.T) {
	rule := CreateRuleByID(R0001ID)
	// Assert r is not nil
	if rule == nil {
		t.Errorf("Expected rule to not be nil")
	}
	// not exist
	rule = CreateRuleByID("not exist")
	// Assert r is not nil
	if rule != nil {
		t.Errorf("Expected rule to be nil")
	}
}
