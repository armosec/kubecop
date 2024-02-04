package rulebindingstore

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/kubescape/kapprofiler/pkg/collector"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
)

const RuntimeRuleBindingAlertPlural = "runtimerulealertbindings"

var RuleBindingAlertGvr schema.GroupVersionResource = schema.GroupVersionResource{
	Group:    collector.ApplicationProfileGroup,
	Version:  collector.ApplicationProfileVersion,
	Resource: RuntimeRuleBindingAlertPlural,
}

type dynClient interface {
	Resource(gvr schema.GroupVersionResource) dynamic.NamespaceableResourceInterface
}

type RuleBindingK8sStore struct {
	dynamicClient       dynClient
	coreV1Client        v1.CoreV1Interface
	informerStopChannel chan struct{}
	nodeName            string
	storeNamespace      string
	// functions to call upon a change in a rule binding
	callBacks []RuleBindingChangedHandler
}

func NewRuleBindingK8sStore(dynamicClient dynClient, coreV1Client v1.CoreV1Interface, nodeName, storeNamespace string) (*RuleBindingK8sStore, error) {

	stopCh := make(chan struct{})
	if storeNamespace == "" {
		storeNamespace = metav1.NamespaceNone
	}

	ruleBindingStore := RuleBindingK8sStore{
		dynamicClient:       dynamicClient,
		informerStopChannel: stopCh,
		nodeName:            nodeName,
		coreV1Client:        coreV1Client,
		storeNamespace:      storeNamespace,
	}
	ruleBindingStore.StartController()
	return &ruleBindingStore, nil
}

func (store *RuleBindingK8sStore) getAllRuleBindings() ([]RuntimeAlertRuleBinding, error) {
	ruleBindingList, err := store.dynamicClient.Resource(RuleBindingAlertGvr).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	ruleBindingListBytes, err := ruleBindingList.MarshalJSON()
	if err != nil {
		return nil, err
	}

	var ruleBindingListObj *RuntimeAlertRuleBindingList
	err = json.Unmarshal(ruleBindingListBytes, &ruleBindingListObj)
	if err != nil {
		return nil, err
	}

	return ruleBindingListObj.Items, nil
}

func (store *RuleBindingK8sStore) getRuleBindingsForPod(podName, namespace string) ([]RuntimeAlertRuleBinding, error) {
	allBindings, err := store.getAllRuleBindings()
	if err != nil {
		return nil, err
	}

	var ruleBindingsForPod []RuntimeAlertRuleBinding
	for _, ruleBinding := range allBindings {
		// check the namespace selector fits the pod namespace
		nsLabelSelector := ruleBinding.Spec.NamespaceSelector
		if nsLabelSelector.MatchLabels == nil {
			nsLabelSelector.MatchLabels = make(map[string]string)
		} else if ns, ok := nsLabelSelector.MatchLabels["kubernetes.io/metadata.name"]; ok && ns != namespace {
			// namespace selector doesn't match the pod namespace
			continue
		}
		// according to https://kubernetes.io/docs/concepts/services-networking/network-policies/#targeting-a-namespace-by-its-name this should do the job
		nsLabelSelector.MatchLabels["kubernetes.io/metadata.name"] = namespace
		selectorString := metav1.FormatLabelSelector(&nsLabelSelector)

		nss, err := store.coreV1Client.Namespaces().List(context.Background(), metav1.ListOptions{LabelSelector: selectorString, Limit: 1})
		if err != nil {
			return nil, fmt.Errorf("failed to get namespaces for selector %s: %v", selectorString, err)
		}
		if len(nss.Items) == 0 {
			continue
		}
		selectorString = metav1.FormatLabelSelector(&ruleBinding.Spec.PodSelector)
		if selectorString == "<none>" {
			// This rule binding applies to all pods in the namespace
			ruleBindingsForPod = append(ruleBindingsForPod, ruleBinding)
			continue
		} else if selectorString == "<error>" {
			return nil, fmt.Errorf("failed to parse pod selector %s", selectorString)
		}
		pods, err := store.coreV1Client.Pods(namespace).List(context.Background(), metav1.ListOptions{
			LabelSelector: selectorString,
			FieldSelector: "spec.nodeName=" + store.nodeName})
		if err != nil {
			return nil, fmt.Errorf("failed to get pods for selector %s: %v", selectorString, err)
		}
		if len(pods.Items) == 0 {
			continue
		}
		for _, pod := range pods.Items {
			if pod.Name == podName {
				ruleBindingsForPod = append(ruleBindingsForPod, ruleBinding)
				break
			}
		}
	}

	return ruleBindingsForPod, nil
}

func (store *RuleBindingK8sStore) GetRulesForPod(podName, namespace string) ([]RuntimeAlertRuleBindingRule, error) {
	// TODO: change to support parameters of rule + custom priority
	ruleBindingsForPod, err := store.getRuleBindingsForPod(podName, namespace)
	if err != nil {
		return nil, err
	}

	// we may have here duplications of rules, this should be handled by the caller logic
	// Issue in GH: https://github.com/armosec/kubecop/issues/30
	var rulesSlice []RuntimeAlertRuleBindingRule
	for _, ruleBinding := range ruleBindingsForPod {
		rulesSlice = append(rulesSlice, ruleBinding.Spec.Rules...)
	}

	return rulesSlice, nil
}

func (store *RuleBindingK8sStore) Destroy() {
	close(store.informerStopChannel)
}

func (store *RuleBindingK8sStore) ruleBindingAddedHandler(obj interface{}) {
	bindObj, err := getRuntimeAlertRuleBindingFromObj(obj)
	if err != nil {
		fmt.Println("Error getting rule binding from obj: ", err)
		return
	}
	fmt.Println("Rule binding added: ", bindObj)
	for _, callBack := range store.callBacks {
		callBack(*bindObj)
	}
}

func (store *RuleBindingK8sStore) ruleBindingUpdatedHandler(oldObj, newObj interface{}) {
	// naive implementation. just call the other handlers
	store.ruleBindingDeletedHandler(oldObj)
	store.ruleBindingAddedHandler(newObj)
}

func (store *RuleBindingK8sStore) ruleBindingDeletedHandler(obj interface{}) {
	bindObj, err := getRuntimeAlertRuleBindingFromObj(obj)
	if err != nil {
		fmt.Println("Error getting rule binding from obj: ", err)
		return
	}
	fmt.Println("Rule binding deleted: ", bindObj)
	for _, callBack := range store.callBacks {
		callBack(*bindObj)
	}
}

func getRuntimeAlertRuleBindingFromObj(obj interface{}) (*RuntimeAlertRuleBinding, error) {
	typedObj := obj.(*unstructured.Unstructured)
	bytes, err := typedObj.MarshalJSON()
	if err != nil {
		return &RuntimeAlertRuleBinding{}, err
	}

	var runtimeAlertRuleBindingObj *RuntimeAlertRuleBinding
	err = json.Unmarshal(bytes, &runtimeAlertRuleBindingObj)
	if err != nil {
		return runtimeAlertRuleBindingObj, err
	}
	return runtimeAlertRuleBindingObj, nil
}

func (store *RuleBindingK8sStore) StartController() {

	// Initialize factory and informer
	informer := dynamicinformer.NewFilteredDynamicSharedInformerFactory(store.dynamicClient, 0, store.storeNamespace, nil).ForResource(RuleBindingAlertGvr).Informer()

	// Add event handlers to informer
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    store.ruleBindingAddedHandler,
		UpdateFunc: store.ruleBindingUpdatedHandler,
		DeleteFunc: store.ruleBindingDeletedHandler,
	})

	// Run the informer
	go informer.Run(store.informerStopChannel)
}

func (store *RuleBindingK8sStore) SetRuleBindingChangedHandlers(handlers []RuleBindingChangedHandler) {
	store.callBacks = handlers
}
