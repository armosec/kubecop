package approfilecache

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/kubescape/kapprofiler/pkg/collector"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

type ApplicationProfileChacheEntry struct {
	ApplicationProfile *collector.ApplicationProfile
	WorkloadName       string
	WorkloadKind       string
	Namespace          string
}

type ApplicationProfileK8sCache struct {
	k8sConfig     *rest.Config
	dynamicClient *dynamic.DynamicClient

	cache                  map[string]*ApplicationProfileChacheEntry
	informerControlChannel chan struct{}
}

type ApplicationProfileAccessImpl struct {
	containerProfile *collector.ContainerProfile
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
	cache := make(map[string]*ApplicationProfileChacheEntry)
	controlChannel := make(chan struct{})
	newApplicationCache := ApplicationProfileK8sCache{k8sConfig: k8sConfig, dynamicClient: dynamicClient, cache: cache, informerControlChannel: controlChannel}
	newApplicationCache.StartController()
	return &newApplicationCache, nil
}

func (cache *ApplicationProfileK8sCache) Destroy() {
	close(cache.informerControlChannel)
}

func (cache *ApplicationProfileK8sCache) HasApplicationProfile(namespace, kind, workloadName, containerName string) bool {
	// Not implemented yet
	return false
}

func (cache *ApplicationProfileK8sCache) LoadApplicationProfile(namespace, kind, workloadName, containerName, containerID string) error {
	appProfile, err := cache.dynamicClient.Resource(collector.AppProfileGvr).Namespace(namespace).Get(context.TODO(), generateApplicationProfileName(kind, workloadName), metav1.GetOptions{})
	if err != nil {
		return err
	}
	applicationProfile, err := getApplicationProfileFromObj(appProfile)
	if err != nil {
		return err
	}
	cache.cache[containerID] = &ApplicationProfileChacheEntry{
		ApplicationProfile: applicationProfile,
		WorkloadName:       workloadName,
		WorkloadKind:       kind,
		Namespace:          namespace,
	}
	return nil
}

func (cache *ApplicationProfileK8sCache) AnticipateApplicationProfile(namespace, kind, workloadName, containerName, containerID string) error {
	cache.cache[containerID] = &ApplicationProfileChacheEntry{
		ApplicationProfile: nil,
		WorkloadName:       workloadName,
		WorkloadKind:       kind,
		Namespace:          namespace,
	}
	return nil
}

func (cache *ApplicationProfileK8sCache) DeleteApplicationProfile(containerID string) error {
	delete(cache.cache, containerID)
	return nil
}

func (cache *ApplicationProfileK8sCache) GetApplicationProfileAccess(containerName, containerID string) (SingleApplicationProfileAccess, error) {
	applicationProfile, ok := cache.cache[containerID]
	if !ok {
		return nil, fmt.Errorf("application profile for container %s", containerID)
	}

	// Check that the application profile is not nil
	if applicationProfile.ApplicationProfile == nil {
		return nil, fmt.Errorf("application profile for container %s is nil (does not exist yet)", containerID)
	}

	for _, containerProfile := range applicationProfile.ApplicationProfile.Spec.Containers {
		if containerProfile.Name == containerName {
			return &ApplicationProfileAccessImpl{containerProfile: &containerProfile}, nil
		} else {
			return nil, fmt.Errorf("container profile %v not found in application profile for container %v", containerName, containerID)
		}
	}
	return nil, fmt.Errorf("container profile %v not found in application profile for container %v", containerName, containerID)
}

func (access *ApplicationProfileAccessImpl) GetExecList() (*[]collector.ExecCalls, error) {
	return &access.containerProfile.Execs, nil
}

func (access *ApplicationProfileAccessImpl) GetOpenList() (*[]collector.OpenCalls, error) {
	return &access.containerProfile.Opens, nil
}

func (access *ApplicationProfileAccessImpl) GetNetworkActivity() (*collector.NetworkActivity, error) {
	return &access.containerProfile.NetworkActivity, nil
}

func (access *ApplicationProfileAccessImpl) GetSystemCalls() ([]string, error) {
	return access.containerProfile.SysCalls, nil
}

func (access *ApplicationProfileAccessImpl) GetCapabilities() ([]collector.CapabilitiesCalls, error) {
	return access.containerProfile.Capabilities, nil
}

func (access *ApplicationProfileAccessImpl) GetDNS() (*[]collector.DnsCalls, error) {
	return &access.containerProfile.Dns, nil
}

func (c *ApplicationProfileK8sCache) StartController() {

	// Initialize factory and informer
	informer := dynamicinformer.NewFilteredDynamicSharedInformerFactory(c.dynamicClient, 0, metav1.NamespaceAll, nil).ForResource(collector.AppProfileGvr).Informer()

	// Add event handlers to informer
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) { // Called when an ApplicationProfile is added
			c.handleApplicationProfile(obj)
		},
		UpdateFunc: func(oldObj, newObj interface{}) { // Called when an ApplicationProfile is updated
			c.handleApplicationProfile(newObj)
		},
		DeleteFunc: func(obj interface{}) { // Called when an ApplicationProfile is deleted
			c.handleDeleteApplicationProfile(obj)
		},
	})

	// Run the informer
	go informer.Run(c.informerControlChannel)
}

func (c *ApplicationProfileK8sCache) handleApplicationProfile(obj interface{}) {
	appProfile, err := getApplicationProfileFromObj(obj)
	if err != nil {
		log.Printf("Failed to get application profile from object: %v\n", err)
		return
	}
	// Check if the application profile is final
	if appProfile.GetAnnotations()["kapprofiler.kubescape.io/final"] != "true" {
		return
	}

	// Convert the application profile name to kind and workload name
	kind, workloadName := strings.Split(appProfile.GetName(), "-")[0], strings.SplitN(appProfile.GetName(), "-", 2)[1]

	// Add the application profile to the cache

	// Loop over the application profile cache entries and check if there is an entry for the same workload
	for _, cacheEntry := range c.cache {
		if cacheEntry.WorkloadName == workloadName && strings.ToLower(cacheEntry.WorkloadKind) == kind && cacheEntry.Namespace == appProfile.GetNamespace() {
			// Update the cache entry
			cacheEntry.ApplicationProfile = appProfile
		}
	}
}

func (c *ApplicationProfileK8sCache) handleDeleteApplicationProfile(obj interface{}) {
	appProfile, err := getApplicationProfileFromObj(obj)
	if err != nil {
		log.Printf("Failed to get application profile from object: %v\n", err)
		return
	}
	// Convert the application profile name to kind and workload name
	kind, workloadName := strings.Split(appProfile.GetName(), "-")[0], strings.Split(appProfile.GetName(), "-")[1]

	// Delete the application profile from the cache
	for key, cacheEntry := range c.cache {
		if cacheEntry.WorkloadName == workloadName && cacheEntry.WorkloadKind == kind && cacheEntry.Namespace == appProfile.GetNamespace() {
			// Delete the cache entry
			delete(c.cache, key)
		}
	}
}
