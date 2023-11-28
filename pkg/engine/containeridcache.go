package engine

import (
	"sync"

	"github.com/armosec/kubecop/pkg/engine/rule"
	corev1 "k8s.io/api/core/v1"
)

type containerEntry struct {
	ContainerID   string
	ContainerName string
	PodName       string
	Namespace     string
	OwnerKind     string
	OwnerName     string
	// Low level container information
	NsMntId uint64

	// Attached late (after container already started)
	AttachedLate bool

	// Pod spec
	PodSpec *corev1.PodSpec

	// Add rules here
	BoundRules []rule.Rule
}

// Container ID to details cache
var containerIdToDetailsCache = make(map[string]containerEntry)
var containerIdToDetailsCacheLock = sync.RWMutex{}

func setContainerDetails(containerId string, containerDetails containerEntry, exists bool) {
	containerIdToDetailsCacheLock.Lock()
	defer containerIdToDetailsCacheLock.Unlock()
	if exists {
		// If the container used to be exist and it's not in the cache, don't add it again
		if _, ok := containerIdToDetailsCache[containerId]; !ok {
			return
		}
	}
	containerIdToDetailsCache[containerId] = containerDetails
}

func getContainerDetails(containerId string) (containerEntry, bool) {
	containerIdToDetailsCacheLock.RLock()
	defer containerIdToDetailsCacheLock.RUnlock()
	containerDetails, ok := containerIdToDetailsCache[containerId]
	return containerDetails, ok
}

func deleteContainerDetails(containerId string) {
	containerIdToDetailsCacheLock.Lock()
	defer containerIdToDetailsCacheLock.Unlock()
	delete(containerIdToDetailsCache, containerId)
}

func getcontainerIdToDetailsCacheCopy() map[string]containerEntry {
	containerIdToDetailsCacheLock.RLock()
	defer containerIdToDetailsCacheLock.RUnlock()
	copy := make(map[string]containerEntry)
	for k, v := range containerIdToDetailsCache {
		copy[k] = v
	}
	return copy
}
