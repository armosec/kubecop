package approfilecache

import (
	"github.com/kubescape/kapprofiler/pkg/collector"
)

type SingleApplicationProfileAccess interface {
	// Get application profile name
	GetName() string
	// Get application profile namespace
	GetNamespace() string
	// Get exec list
	GetExecList() (*[]collector.ExecCalls, error)
	// Get open list
	GetOpenList() (*[]collector.OpenCalls, error)
	// Get network activity
	GetNetworkActivity() (*collector.NetworkActivity, error)
	// Get system calls
	GetSystemCalls() ([]string, error)
	// Get capabilities
	GetCapabilities() (*[]collector.CapabilitiesCalls, error)
	// Get DNS activity
	GetDNS() (*[]collector.DnsCalls, error)
}

type ApplicationProfileCache interface {
	// Load an application profile to the cache
	LoadApplicationProfile(namespace, kind, workloadName, ownerKind, ownerName, containerName, containerID string, acceptPartial bool) error

	// Anticipate an application profile to be loaded to the cache
	AnticipateApplicationProfile(namespace, kind, workloadName, ownerKind, ownerName, containerName, containerID string, acceptPartial bool) error

	// Delete an application profile from the cache
	DeleteApplicationProfile(containerID string) error

	// Has application profile for the given container in Kubernetes workload (identified by namespace, kind, workload name and container name)
	HasApplicationProfile(namespace, kind, workloadName, containerName string) bool

	// Get application profile access for the given container in Kubernetes workload (identified by container name and ID in the cache)
	GetApplicationProfileAccess(containerName, containerID string) (SingleApplicationProfileAccess, error)
}
