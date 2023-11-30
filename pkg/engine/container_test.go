package engine

import (
	"testing"

	"github.com/armosec/kubecop/pkg/engine/rule"
	"github.com/armosec/kubecop/pkg/rulebindingstore"
	"github.com/stretchr/testify/assert"
)

func TestAssociateRulesWithContainerInCache(t *testing.T) {
	engine := &Engine{} // Create an instance of the Engine struct

	// Define the test input
	contEntry := containerEntry{
		PodName:     "test-pod",
		Namespace:   "test-namespace",
		ContainerID: "test-container",
	}

	// Mock the getRulesForPodFunc function
	engine.getRulesForPodFunc = func(podName, namespace string) ([]rulebindingstore.RuntimeAlertRuleBindingRule, error) {
		// Return some mock rule parameters
		return []rulebindingstore.RuntimeAlertRuleBindingRule{
			{
				RuleName: rule.R0001UnexpectedProcessLaunchedRuleDescriptor.Name,
			},
			{
				RuleID: rule.R0002UnexpectedFileAccessRuleDescriptor.ID,
			},
			{
				RuleTags: rule.R0003UnexpectedSystemCallRuleDescriptor.Tags,
			},
		}, nil
	}

	// Call the method first with exists=true, then with exists=false
	exists := true
	err := engine.associateRulesWithContainerInCache(contEntry, exists)

	// Check the result
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	// get from cache
	_, ok := getContainerDetails(contEntry.ContainerID)
	if ok {
		t.Errorf("Container details should not found in cache in this case")
	}
	// Call the method again with exists=false
	exists = false
	err = engine.associateRulesWithContainerInCache(contEntry, exists)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	// get from cache
	contDetFromCache, ok := getContainerDetails(contEntry.ContainerID)
	if !ok {
		t.Errorf("Container details not found in cache")
	}

	// check the container details fields
	assert.Equal(t, contEntry.ContainerID, contDetFromCache.ContainerID)
	assert.Equal(t, contEntry.PodName, contDetFromCache.PodName)
	assert.Equal(t, contEntry.Namespace, contDetFromCache.Namespace)

	// Check the bound rules
	expectedRuleDescs := []rule.Rule{
		rule.CreateRuleByName(rule.R0001UnexpectedProcessLaunchedRuleDescriptor.Name),
		rule.CreateRuleByID(rule.R0002UnexpectedFileAccessRuleDescriptor.ID),
	}
	expectedRuleDescs = append(expectedRuleDescs, rule.CreateRulesByTags(rule.R0003UnexpectedSystemCallRuleDescriptor.Tags)...)
	assert.Equal(t, expectedRuleDescs, contDetFromCache.BoundRules)

	// delete from cache
	deleteContainerDetails(contEntry.ContainerID)
	_, ok = getContainerDetails(contEntry.ContainerID)
	if ok {
		t.Errorf("Container details should not found in cache after deletion")
	}
}
