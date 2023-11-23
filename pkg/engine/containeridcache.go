package engine

import (
	"sync"

	"github.com/armosec/kubecop/pkg/engine/rule"
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

	// Add rules here
	BoundRules []rule.Rule
}

// Container ID to details cache
var containerIdToDetailsCache = make(map[string]containerEntry)
var containerIdToDetailsCacheLock = sync.RWMutex{}

func setContainerDetails(containerId string, containerDetails containerEntry) {
	containerIdToDetailsCacheLock.Lock()
	defer containerIdToDetailsCacheLock.Unlock()
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
