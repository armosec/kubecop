package rulebindingstore

import (
	"embed"
	"io/fs"
	"sort"
	"testing"

	corev1 "k8s.io/api/core/v1"
	dfake "k8s.io/client-go/dynamic/fake"

	"github.com/armosec/kubecop/pkg/engine/rule"
	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer/yaml"
	"k8s.io/client-go/kubernetes/fake"
)

func TestNewRuleBindingK8sStore(t *testing.T) {
	// Create a fake dynamic client
	dynamicClient := dfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{RuleBindingAlertGvr: RuntimeRuleBindingAlertPlural + "List"}, ruleBindingsObjects()...)
	// Create a fake core client
	coreClient := fake.NewSimpleClientset(coreV1Objects()...).CoreV1()
	// Create a RuleBindingK8sStore instance
	store, err := NewRuleBindingK8sStore(dynamicClient, coreClient, "test-node", "")
	assert.NoError(t, err)
	defer store.Destroy()
	assert.NotNil(t, store)
}

func TestRuleBindingK8sStore_getAllRuleBindings(t *testing.T) {
	// Create a fake dynamic client
	dynamicClient := dfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{RuleBindingAlertGvr: RuntimeRuleBindingAlertPlural + "List"}, ruleBindingsObjects()...)
	// Create a fake core client
	coreClient := fake.NewSimpleClientset(coreV1Objects()...).CoreV1()
	// Create a RuleBindingK8sStore instance
	store, err := NewRuleBindingK8sStore(dynamicClient, coreClient, "test-node", "")
	assert.NoError(t, err)
	defer store.Destroy()

	// Call the getAllRuleBindings function
	ruleBindings, err := store.getAllRuleBindings()
	sort.Slice(ruleBindings, func(i, j int) bool {
		return ruleBindings[i].Name < ruleBindings[j].Name
	})
	assert.NoError(t, err)
	assert.Len(t, ruleBindings, 6)
	assert.Equal(t, "all-rules-all-pods", ruleBindings[0].Name)
	assert.Equal(t, 0, len(ruleBindings[1].Spec.NamespaceSelector.MatchLabels))
	assert.Equal(t, "all-rules-for-app-nginx", ruleBindings[1].Name)
}

func TestRuleBindingK8sStore_getRuleBindingsForPod(t *testing.T) {
	// Create a fake dynamic client
	dynamicClient := dfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{RuleBindingAlertGvr: RuntimeRuleBindingAlertPlural + "List"}, ruleBindingsObjects()...)
	// Create a fake core client
	coreClient := fake.NewSimpleClientset(coreV1Objects()...).CoreV1()
	// Create a RuleBindingK8sStore instance
	store, err := NewRuleBindingK8sStore(dynamicClient, coreClient, "test-node", "")
	assert.NoError(t, err)
	defer store.Destroy()

	// Call the getRuleBindingsForPod function
	ruleBindings, err := store.getRuleBindingsForPod("test-pod", "test-namespace")
	assert.NoError(t, err)
	// only "all-rules-all-pods" should match
	assert.Len(t, ruleBindings, 1)
	assert.Equal(t, "all-rules-all-pods", ruleBindings[0].Name)
	number_of_all_rules := len(rule.GetAllRuleDescriptors())
	assert.Equal(t, number_of_all_rules, len(ruleBindings[0].Spec.Rules))
}

func TestRuleBindingK8sStore_GetRulesForPod(t *testing.T) {
	// Create a fake dynamic client
	dynamicClient := dfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{RuleBindingAlertGvr: RuntimeRuleBindingAlertPlural + "List"}, ruleBindingsObjects()...)
	// Create a fake core client
	coreClient := fake.NewSimpleClientset(coreV1Objects()...).CoreV1()
	// Create a RuleBindingK8sStore instance
	store, err := NewRuleBindingK8sStore(dynamicClient, coreClient, "test-node", "")
	assert.NoError(t, err)
	defer store.Destroy()
	// Call the GetRulesForPod function
	rules, err := store.GetRulesForPod("test-pod", "test-namespace")
	assert.NoError(t, err)
	number_of_all_rules := len(rule.GetAllRuleDescriptors())
	assert.Len(t, rules, number_of_all_rules)
}

//go:embed testdata/rulebindingsfiles/*.yaml
var rulebindingsfiles embed.FS

func ruleBindingsObjects() []runtime.Object {
	rules := []runtime.Object{}
	// Read all YAML files in the testdata/rulebindingsfiles directory

	err := fs.WalkDir(rulebindingsfiles, "testdata/rulebindingsfiles", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}
		ruleBinding3 := unstructured.Unstructured{}
		decUnstructured := yaml.NewDecodingSerializer(unstructured.UnstructuredJSONScheme)
		ruleBytes, err := fs.ReadFile(rulebindingsfiles, path)
		if err != nil {
			return err
		}

		if _, _, err := decUnstructured.Decode(ruleBytes, nil, &ruleBinding3); err != nil {
			return err
		}
		rules = append(rules, &ruleBinding3)

		return nil
	})

	if err != nil {
		panic(err)
	}
	return rules
}

func coreV1Objects() []runtime.Object {
	nginxpod1 := corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginxpod1",
			Namespace: "test-namespace",
			Labels: map[string]string{
				"app": "test-app",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "test-node",
		},
	}
	nginxpodDefaultNS := corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "nginxpod1",
			Namespace: "default",
			Labels: map[string]string{
				"app": "test-app",
			},
		},
	}

	defaultNS := corev1.Namespace{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Namespace",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
			Labels: map[string]string{
				"kubernetes.io/metadata.name": "default",
			},
		},
	}

	testNS := corev1.Namespace{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Namespace",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-namespace",
			Labels: map[string]string{
				"kubernetes.io/metadata.name": "test-namespace",
			},
		},
	}

	return []runtime.Object{&nginxpod1, &nginxpodDefaultNS, &defaultNS, &testNS}
}
