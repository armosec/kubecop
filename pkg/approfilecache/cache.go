package approfilecache

import (
	"context"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/kubescape/kapprofiler/pkg/collector"
	"github.com/kubescape/kapprofiler/pkg/watcher"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
)

type ApplicationProfileCacheEntry struct {
	ApplicationProfile *collector.ApplicationProfile
	WorkloadName       string
	WorkloadKind       string
	OwnerName          string
	OwnerKind          string
	Namespace          string
	AcceptPartial      bool
	OwnerLevelProfile  bool
}

type ApplicationProfileK8sCache struct {
	dynamicClient dynamic.Interface
	cache         map[string]ApplicationProfileCacheEntry

	applicationProfileWatcher watcher.WatcherInterface

	promCollector *prometheusMetric
}

type ApplicationProfileAccessImpl struct {
	containerProfile    *collector.ContainerProfile
	appProfileName      string
	appProfileNamespace string
}

func generateApplicationProfileName(kind, workloadName string) string {
	return strings.ToLower(kind) + "-" + workloadName
}

func getApplicationProfileFromUnstructured(typedObj *unstructured.Unstructured) (*collector.ApplicationProfile, error) {
	var applicationProfileObj collector.ApplicationProfile
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(typedObj.Object, &applicationProfileObj)
	if err != nil {
		return &collector.ApplicationProfile{}, err
	}
	return &applicationProfileObj, nil
}

func NewApplicationProfileK8sCache(dynamicClient dynamic.Interface) (*ApplicationProfileK8sCache, error) {
	cache := make(map[string]ApplicationProfileCacheEntry)
	newApplicationCache := ApplicationProfileK8sCache{
		dynamicClient:             dynamicClient,
		cache:                     cache,
		applicationProfileWatcher: watcher.NewWatcher(dynamicClient, false), // No need to pre-list the application profiles since the container start will look for them
		promCollector:             createPrometheusMetric(),
	}
	newApplicationCache.StartController()
	return &newApplicationCache, nil
}

func (cache *ApplicationProfileK8sCache) Destroy() {
	if cache.applicationProfileWatcher != nil {
		cache.applicationProfileWatcher.Stop()
	}
	cache.promCollector.destroy()
}

func (cache *ApplicationProfileK8sCache) HasApplicationProfile(namespace, kind, workloadName, containerName string) bool {
	// Not implemented yet
	return false
}

func (cache *ApplicationProfileK8sCache) LoadApplicationProfile(namespace, kind, workloadName, ownerKind, ownerName, containerName, containerID string, acceptPartial bool) error {
	ownerLevel := true
	appProfile, err := cache.dynamicClient.Resource(collector.AppProfileGvr).Namespace(namespace).Get(context.TODO(), generateApplicationProfileName(ownerKind, ownerName), metav1.GetOptions{})
	if err != nil {
		// Failed to get the application profile at the owner level, try to get it at the workload level
		appProfile, err = cache.dynamicClient.Resource(collector.AppProfileGvr).Namespace(namespace).Get(context.TODO(), generateApplicationProfileName(kind, workloadName), metav1.GetOptions{})
		if err != nil {
			// Failed to get the application profile at the workload level as well, return the error
			return err
		}
		ownerLevel = false
	}
	applicationProfile, err := getApplicationProfileFromUnstructured(appProfile)
	if err != nil {
		return err
	}
	if applicationProfile.GetLabels()["kapprofiler.kubescape.io/final"] != "true" {
		// The application profile is not final, return an error
		return fmt.Errorf("application profile %s is not final", applicationProfile.GetName())
	}

	cache.cache[containerID] = ApplicationProfileCacheEntry{
		ApplicationProfile: applicationProfile,
		WorkloadName:       workloadName,
		WorkloadKind:       strings.ToLower(kind),
		OwnerName:          ownerName,
		OwnerKind:          strings.ToLower(ownerKind),
		Namespace:          namespace,
		AcceptPartial:      acceptPartial,
		OwnerLevelProfile:  ownerLevel,
	}
	return nil
}

func (cache *ApplicationProfileK8sCache) AnticipateApplicationProfile(namespace, kind, workloadName, ownerKind, ownerName, containerName, containerID string, acceptPartial bool) error {
	cache.cache[containerID] = ApplicationProfileCacheEntry{
		ApplicationProfile: nil,
		WorkloadName:       workloadName,
		WorkloadKind:       strings.ToLower(kind),
		OwnerName:          ownerName,
		OwnerKind:          strings.ToLower(ownerKind),
		Namespace:          namespace,
		AcceptPartial:      acceptPartial,
	}
	return nil
}

func (cache *ApplicationProfileK8sCache) DeleteApplicationProfile(containerID string) error {
	if item, ok := cache.cache[containerID]; ok {
		item.ApplicationProfile = nil
		delete(cache.cache, containerID)
	}

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
			return &ApplicationProfileAccessImpl{containerProfile: &containerProfile,
				appProfileName:      applicationProfile.ApplicationProfile.Name,
				appProfileNamespace: applicationProfile.Namespace,
			}, nil
		}
	}
	return nil, fmt.Errorf("container profile %v not found in application profile for container %v", containerName, containerID)
}

func (access *ApplicationProfileAccessImpl) GetName() string {
	return access.appProfileName
}

func (access *ApplicationProfileAccessImpl) GetNamespace() string {
	return access.appProfileNamespace
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

func (access *ApplicationProfileAccessImpl) GetCapabilities() (*[]collector.CapabilitiesCalls, error) {
	return &access.containerProfile.Capabilities, nil
}

func (access *ApplicationProfileAccessImpl) GetDNS() (*[]collector.DnsCalls, error) {
	return &access.containerProfile.Dns, nil
}

func (c *ApplicationProfileK8sCache) StartController() {

	err := c.applicationProfileWatcher.Start(
		watcher.WatchNotifyFunctions{
			AddFunc: func(obj *unstructured.Unstructured) {
				c.promCollector.createCounter.Inc()
				c.handleApplicationProfile(obj)
			},
			UpdateFunc: func(obj *unstructured.Unstructured) {
				c.promCollector.updateCounter.Inc()
				c.handleApplicationProfile(obj)
			},
			DeleteFunc: func(obj *unstructured.Unstructured) {
				c.promCollector.deleteCounter.Inc()
				c.handleDeleteApplicationProfile(obj)
			},
		},
		collector.AppProfileGvr,
		metav1.ListOptions{
			LabelSelector: "kapprofiler.kubescape.io/final=true",
		},
	)

	if err != nil {
		log.Errorf("Failed to start application profile watcher: %v\n", err)
	}
}

func (c *ApplicationProfileK8sCache) handleApplicationProfile(appProfileUnstructured *unstructured.Unstructured) {
	partial := appProfileUnstructured.GetLabels()["kapprofiler.kubescape.io/partial"] == "true"
	final := appProfileUnstructured.GetLabels()["kapprofiler.kubescape.io/final"] == "true"
	failed := appProfileUnstructured.GetLabels()["kapprofiler.kubescape.io/failed"] == "true"

	// Check if the application profile is final or partial, if not then skip it
	if !final || failed {
		return
	}

	// Convert the application profile name to kind and workload name
	kind, workloadName := strings.Split(appProfileUnstructured.GetName(), "-")[0], strings.SplitN(appProfileUnstructured.GetName(), "-", 2)[1]

	// Add the application profile to the cache

	// Loop over the application profile cache entries and check if there is an entry for the same workload
	for id, cacheEntry := range c.cache {
		if cacheEntry.Namespace == appProfileUnstructured.GetNamespace() {
			if !cacheEntry.AcceptPartial && partial {
				// Skip the partial application profile becuase we expect a final one
				continue
			}
			if (cacheEntry.WorkloadName == workloadName && cacheEntry.WorkloadKind == kind) ||
				(cacheEntry.OwnerName == workloadName && cacheEntry.OwnerKind == kind) {
				appProfile, err := getApplicationProfileFromUnstructured(appProfileUnstructured)
				if err != nil {
					log.Errorf("Failed to get application profile from object: %v\n", err)
					return
				}

				log.Printf("Updating application profile %s for workload %s/%s\n", appProfile.GetName(), cacheEntry.Namespace, cacheEntry.WorkloadName)

				// Update the cache entry
				cacheEntry.ApplicationProfile = appProfile
				c.cache[id] = cacheEntry
				continue
			}
		}
	}
}

func (c *ApplicationProfileK8sCache) handleDeleteApplicationProfile(obj *unstructured.Unstructured) {
	appProfile, err := getApplicationProfileFromUnstructured(obj)
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
