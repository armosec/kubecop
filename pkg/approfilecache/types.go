package approfilecache

import (
	"github.com/kubescape/kapprofiler/pkg/collector"
)

type SingleApplicationProfileAccess interface {
	// Get exec list
	GetExecList() (*[]collector.ExecCalls, error)
	// Get open list
	GetOpenList() (*[]collector.OpenCalls, error)
	// Get network activity
	GetNetworkActivity() (*collector.NetworkActivity, error)
	// Get system calls
	GetSystemCalls() ([]string, error)
	// Get capabilities
	GetCapabilities() ([]collector.CapabilitiesCalls, error)
}

type ApplicationProfileCache interface {
	// Load an application profile to the cache
	LoadApplicationProfile(namespace, kind, workloadName, containerName string) error

	// Delete an application profile from the cache
	DeleteApplicationProfile(namespace, kind, workloadName, containerName string) error

	// Has application profile for the given container in Kubernetes workload (identified by namespace, kind, workload name and container name)
	HasApplicationProfile(namespace, kind, workloadName, containerName string) bool

	// Get application profile access for the given container in Kubernetes workload (identified by namespace, kind, workload name and container name)
	GetApplicationProfileAccess(namespace, kind, workloadName, containerName string) (SingleApplicationProfileAccess, error)

	// Get exec profile for the given container in Kubernetes workload (identified by namespace, kind, workload name and container name)
	GetApplicationProfileExecCalls(namespace, kind, workloadName, containerName string) (*[]collector.ExecCalls, error)

	// Get open profile for the given container in Kubernetes workload (identified by namespace, kind, workload name and container name)
	GetApplicationProfileOpenCalls(namespace, kind, workloadName, containerName string) (*[]collector.OpenCalls, error)

	// Get network profile for the given container in Kubernetes workload (identified by namespace, kind, workload name and container name)
	GetApplicationProfileNetworkCalls(namespace, kind, workloadName, containerName string) (*collector.NetworkActivity, error)

	// Get system calls profile for the given container in Kubernetes workload (identified by namespace, kind, workload name and container name)
	GetApplicationProfileSystemCalls(namespace, kind, workloadName, containerName string) ([]string, error)

	// Get capabilities profile for the given container in Kubernetes workload (identified by namespace, kind, workload name and container name)
	GetApplicationProfileCapabilities(namespace, kind, workloadName, containerName string) ([]collector.CapabilitiesCalls, error)

	// Get DNS profile for the given container in Kubernetes workload (identified by namespace, kind, workload name and container name)
	GetApplicationProfileDNS(namespace, kind, workloadName, containerName string) ([]collector.DnsCalls, error)
}
