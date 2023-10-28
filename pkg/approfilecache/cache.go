package approfilecache

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kubescape/kapprofiler/pkg/collector"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

type ApplicationProfileK8sCache struct {
	k8sConfig     *rest.Config
	dynamicClient *dynamic.DynamicClient

	cache map[string]*collector.ApplicationProfile
}

func generateApplicationProfileName(kind, workloadName string) string {
	return strings.ToLower(kind) + "-" + workloadName
}

func generateCachedApplicationProfileKey(namespace, kind, workloadName string) string {
	return namespace + "-" + kind + "-" + workloadName
}

// Helper function to convert interface to ApplicationProfile
func getApplicationProfileFromObj(obj interface{}) (*collector.ApplicationProfile, error) {
	typedObj := obj.(*unstructured.Unstructured)
	bytes, err := typedObj.MarshalJSON()
	if err != nil {
		return &collector.ApplicationProfile{}, err
	}

	var applicationProfileObj *collector.ApplicationProfile
	err = json.Unmarshal(bytes, &applicationProfileObj)
	if err != nil {
		return applicationProfileObj, err
	}
	return applicationProfileObj, nil
}

func NewApplicationProfileK8sCache(k8sConfig *rest.Config) (*ApplicationProfileK8sCache, error) {
	dynamicClient, err := dynamic.NewForConfig(k8sConfig)
	if err != nil {
		return nil, err
	}
	cache := make(map[string]*collector.ApplicationProfile)
	return &ApplicationProfileK8sCache{k8sConfig: k8sConfig, dynamicClient: dynamicClient, cache: cache}, nil
}

func (cache *ApplicationProfileK8sCache) HasApplicationProfile(namespace, kind, workloadName, containerName string) bool {
	_, ok := cache.cache[generateCachedApplicationProfileKey(namespace, kind, workloadName)]
	return ok
}

func (cache *ApplicationProfileK8sCache) LoadApplicationProfile(namespace, kind, workloadName, containerName string) error {
	appProfile, err := cache.dynamicClient.Resource(collector.AppProfileGvr).Namespace(namespace).Get(context.TODO(), generateApplicationProfileName(kind, workloadName), metav1.GetOptions{})
	if err != nil {
		return err
	}
	applicationProfile, err := getApplicationProfileFromObj(appProfile)
	if err != nil {
		return err
	}
	cache.cache[generateCachedApplicationProfileKey(namespace, kind, workloadName)] = applicationProfile
	return nil
}

func (cache *ApplicationProfileK8sCache) DeleteApplicationProfile(namespace, kind, workloadName, containerName string) error {
	delete(cache.cache, generateCachedApplicationProfileKey(namespace, kind, workloadName))
	return nil
}

func (cache *ApplicationProfileK8sCache) GetApplicationProfileExecCalls(namespace, kind, workloadName, containerName string) (*[]collector.ExecCalls, error) {
	applicationProfile, ok := cache.cache[generateCachedApplicationProfileKey(namespace, kind, workloadName)]
	if !ok {
		return nil, fmt.Errorf("application profile for workload %v of kind %v in namespace %v not found", workloadName, kind, namespace)
	}
	for _, containerProfile := range applicationProfile.Spec.Containers {
		if containerProfile.Name == containerName {
			return &containerProfile.Execs, nil
		}
	}
	return nil, fmt.Errorf("container profile %v not found in application profile for workload %v of kind %v in namespace %v", containerName, workloadName, kind, namespace)
}

func (cache *ApplicationProfileK8sCache) GetApplicationProfileOpenCalls(namespace, kind, workloadName, containerName string) (*[]collector.OpenCalls, error) {
	applicationProfile, ok := cache.cache[generateCachedApplicationProfileKey(namespace, kind, workloadName)]
	if !ok {
		return nil, fmt.Errorf("application profile for workload %v of kind %v in namespace %v not found", workloadName, kind, namespace)
	}
	for _, containerProfile := range applicationProfile.Spec.Containers {
		if containerProfile.Name == containerName {
			return &containerProfile.Opens, nil
		}
	}
	return nil, fmt.Errorf("container profile %v not found in application profile for workload %v of kind %v in namespace %v", containerName, workloadName, kind, namespace)
}

func (cache *ApplicationProfileK8sCache) GetApplicationProfileNetworkCalls(namespace, kind, workloadName, containerName string) (*collector.NetworkActivity, error) {
	applicationProfile, ok := cache.cache[generateCachedApplicationProfileKey(namespace, kind, workloadName)]
	if !ok {
		return nil, fmt.Errorf("application profile for workload %v of kind %v in namespace %v not found", workloadName, kind, namespace)
	}
	for _, containerProfile := range applicationProfile.Spec.Containers {
		if containerProfile.Name == containerName {
			return &containerProfile.NetworkActivity, nil
		}
	}
	return nil, fmt.Errorf("container profile %v not found in application profile for workload %v of kind %v in namespace %v", containerName, workloadName, kind, namespace)
}

func (cache *ApplicationProfileK8sCache) GetApplicationProfileSystemCalls(namespace, kind, workloadName, containerName string) ([]string, error) {
	applicationProfile, ok := cache.cache[generateCachedApplicationProfileKey(namespace, kind, workloadName)]
	if !ok {
		return nil, fmt.Errorf("application profile for workload %v of kind %v in namespace %v not found", workloadName, kind, namespace)
	}
	for _, containerProfile := range applicationProfile.Spec.Containers {
		if containerProfile.Name == containerName {
			return containerProfile.SysCalls, nil
		}
	}
	return nil, fmt.Errorf("container profile %v not found in application profile for workload %v of kind %v in namespace %v", containerName, workloadName, kind, namespace)
}

func (cache *ApplicationProfileK8sCache) GetApplicationProfileCapabilities(namespace, kind, workloadName, containerName string) ([]collector.CapabilitiesCalls, error) {
	applicationProfile, ok := cache.cache[generateCachedApplicationProfileKey(namespace, kind, workloadName)]
	if !ok {
		return nil, fmt.Errorf("application profile for workload %v of kind %v in namespace %v not found", workloadName, kind, namespace)
	}
	for _, containerProfile := range applicationProfile.Spec.Containers {
		if containerProfile.Name == containerName {
			return containerProfile.Capabilities, nil
		}
	}
	return nil, fmt.Errorf("container profile %v not found in application profile for workload %v of kind %v in namespace %v", containerName, workloadName, kind, namespace)
}

func (cache *ApplicationProfileK8sCache) GetApplicationProfileDNS(namespace, kind, workloadName, containerName string) ([]collector.DnsCalls, error) {
	applicationProfile, ok := cache.cache[generateCachedApplicationProfileKey(namespace, kind, workloadName)]
	if !ok {
		return nil, fmt.Errorf("application profile for workload %v of kind %v in namespace %v not found", workloadName, kind, namespace)
	}
	for _, containerProfile := range applicationProfile.Spec.Containers {
		if containerProfile.Name == containerName {
			return containerProfile.Dns, nil
		}
	}
	return nil, fmt.Errorf("container profile %v not found in application profile for workload %v of kind %v in namespace %v", containerName, workloadName, kind, namespace)
}
