package rulebindingstore

import (
	"testing"

	dfake "k8s.io/client-go/dynamic/fake"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

func TestNewRuleBindingK8sStore(t *testing.T) {
	// Create a fake dynamic client
	dynamicClient := dfake.NewSimpleDynamicClient(runtime.NewScheme(), runtimeObjects()...)
	// Create a fake core client
	coreClient := fake.NewSimpleClientset(runtimeObjects()...).CoreV1()

	// Call the NewRuleBindingK8sStore function
	store, err := NewRuleBindingK8sStore(dynamicClient, coreClient, "test-node")
	assert.NoError(t, err)
	defer store.Destroy()
	assert.NotNil(t, store)

}

func TestRuleBindingK8sStore_getAllRuleBindings(t *testing.T) {
	// Create a fake dynamic client
	dynamicClient := dfake.NewSimpleDynamicClient(runtime.NewScheme(), runtimeObjects()...)
	// Create a fake core client
	coreClient := fake.NewSimpleClientset(runtimeObjects()...).CoreV1()
	// Create a RuleBindingK8sStore instance
	store, err := NewRuleBindingK8sStore(dynamicClient, coreClient, "test-node")
	assert.NoError(t, err)
	defer store.Destroy()

	// Call the getAllRuleBindings function
	ruleBindings, err := store.getAllRuleBindings()
	assert.NoError(t, err)
	assert.Len(t, ruleBindings, 2)
}

func TestRuleBindingK8sStore_getRuleBindingsForPod(t *testing.T) {
	// Create a fake dynamic client
	dynamicClient := dfake.NewSimpleDynamicClient(runtime.NewScheme(), runtimeObjects()...)
	// Create a fake core client
	coreClient := fake.NewSimpleClientset(runtimeObjects()...).CoreV1()
	// Create a RuleBindingK8sStore instance
	store, err := NewRuleBindingK8sStore(dynamicClient, coreClient, "test-node")
	assert.NoError(t, err)

	// Call the getRuleBindingsForPod function
	ruleBindings, err := store.getRuleBindingsForPod("test-pod", "test-namespace")
	assert.NoError(t, err)
	assert.Len(t, ruleBindings, 1)
}

func TestRuleBindingK8sStore_GetRulesForPod(t *testing.T) {
	// Create a fake dynamic client
	dynamicClient := dfake.NewSimpleDynamicClient(runtime.NewScheme(), runtimeObjects()...)
	// Create a fake core client
	coreClient := fake.NewSimpleClientset(runtimeObjects()...).CoreV1()
	// Create a RuleBindingK8sStore instance
	store, err := NewRuleBindingK8sStore(dynamicClient, coreClient, "test-node")
	assert.NoError(t, err)
	// Call the GetRulesForPod function
	rules, err := store.GetRulesForPod("test-pod", "test-namespace")
	assert.NoError(t, err)
	assert.Len(t, rules, 2)
}

func runtimeObjects() []runtime.Object {
	ruleBinding1 := unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "kubescape.armosec.com/v1alpha1",
			"kind":       "RuntimeAlertRuleBinding",
			"metadata": map[string]interface{}{
				"name":      "rule-binding-1",
				"namespace": "test-namespace",
			},
			"spec": map[string]interface{}{
				"namespaceSelector": map[string]interface{}{
					"matchLabels": map[string]interface{}{
						"kubernetes.io/metadata.name": "test-namespace",
					},
				},
				"podSelector": map[string]interface{}{
					"matchLabels": map[string]interface{}{
						"app": "test-app",
					},
				},
				"rules": []interface{}{
					map[string]interface{}{
						"ruleName": "rule-1",
					},
				},
			},
		},
	}

	ruleBinding2 := unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "kubescape.armosec.com/v1alpha1",
			"kind":       "RuntimeAlertRuleBinding",
			"metadata": map[string]interface{}{
				"name":      "rule-binding-2",
				"namespace": "test-namespace",
			},
			"spec": map[string]interface{}{
				"namespaceSelector": map[string]interface{}{
					"matchLabels": map[string]interface{}{
						"kubernetes.io/metadata.name": "test-namespace",
					},
				},
				"podSelector": map[string]interface{}{
					"matchLabels": map[string]interface{}{
						"app": "test-app",
					},
				},
				"rules": []interface{}{
					map[string]interface{}{
						"ruleName": "rule-2",
					},
				},
			},
		},
	}

	return []runtime.Object{&ruleBinding1, &ruleBinding2}
}
