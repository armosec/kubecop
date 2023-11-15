package main

import (
	"fmt"

	"github.com/armosec/kubecop/pkg/engine/rule"
)

// Main
func main() {
	// Print out a markdown table containing all the rules
	fmt.Printf("| ID | Rule | Description | Tags | Priority | Application profile |\n")
	fmt.Printf("|----|------|-------------|------|----------|---------------------|\n")
	for _, rule := range rule.GetAllRuleDescriptors() {
		fmt.Printf("| %s | %s | %s | %s | %d | %v |\n", rule.ID, rule.Name, rule.Description, rule.Tags, rule.Priority, rule.Requirements.NeedApplicationProfile)
	}
}
