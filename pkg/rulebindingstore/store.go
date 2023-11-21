package rulebindingstore

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/kubescape/kapprofiler/pkg/collector"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

const RuntimeRuleBindingAlertPlural = "runtimerulealertbindings"

var RuleBindingAlertGvr schema.GroupVersionResource = schema.GroupVersionResource{
	Group:    collector.ApplicationProfileGroup,
	Version:  collector.ApplicationProfileVersion,
	Resource: RuntimeRuleBindingAlertPlural,
}

type RuleBindingK8sStore struct {
	k8sConfig           *rest.Config
	dynamicClient       *dynamic.DynamicClient
	coreV1Client        v1.CoreV1Interface
	informerStopChannel chan struct{}
	nodeName            string
	// functions to call upon a change in a rule binding
	callBacks []RuleBindingChangedHandler
}

func NewRuleBindingK8sStore(k8sConfig *rest.Config, nodeName string) (*RuleBindingK8sStore, error) {
	dynamicClient, err := dynamic.NewForConfig(k8sConfig)
	if err != nil {
		return nil, err
	}

	controlChannel := make(chan struct{})
	ruleBindingStore := RuleBindingK8sStore{k8sConfig: k8sConfig, dynamicClient: dynamicClient, informerStopChannel: controlChannel, nodeName: nodeName}
	ruleBindingStore.initPodsClient()
	ruleBindingStore.StartController()
	return &ruleBindingStore, nil
}

func (store *RuleBindingK8sStore) initPodsClient() {
	clientset, err := kubernetes.NewForConfig(store.k8sConfig)
	if err != nil {
		log.Fatalf("Error creating clientset: %v", err)
	}
	store.coreV1Client = clientset.CoreV1()
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

func (store *RuleBindingK8sStore) GetRulesForPod(podName, namespace string) ([]string, error) {
	// TODO: change to support parameters of rule + custom priority
	ruleBindingsForPod, err := store.getRuleBindingsForPod(podName, namespace)
	if err != nil {
		return nil, err
	}
	rules := make(map[string]struct{})
	for _, ruleBinding := range ruleBindingsForPod {
		for _, rule := range ruleBinding.Spec.Rules {
			rules[rule.RuleName] = struct{}{}
		}
	}
	var rulesSlice []string
	for rule := range rules {
		rulesSlice = append(rulesSlice, rule)
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
	informer := dynamicinformer.NewFilteredDynamicSharedInformerFactory(store.dynamicClient, 0, metav1.NamespaceNone, nil).ForResource(RuleBindingAlertGvr).Informer()

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
