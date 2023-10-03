package collector

import (
	"github.com/kubescape/kapprofiler/pkg/eventsink"
	"github.com/kubescape/kapprofiler/pkg/tracing"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type ContainerId struct {
	Namespace string
	PodName   string
	Container string
	// Low level identifiers
	ContainerID string
	NsMntId     uint64
}

type ContainerState struct {
	running bool
}

type CollectorManager struct {
	// Map of container ID to container state
	containers map[ContainerId]*ContainerState
	// Kubernetes connection clien
	k8sClient *kubernetes.Clientset
	// Event sink
	eventSink *eventsink.EventSink
	// Tracer
	tracer tracing.ITracer
	// config
	config CollectorManagerConfig
	// Application profiles
	applicationProfiles ApplicationProfiles
}

type CollectorManagerConfig struct {
	// Event sink object
	EventSink *eventsink.EventSink
	// Interval in seconds for collecting data from containers
	Interval uint64
	// Kubernetes configuration
	K8sConfig *rest.Config
	// Tracer object
	Tracer tracing.ITracer
	// Application profiles
	ApplicationProfiles ApplicationProfiles
}

type ExecCalls struct {
	Path string   `json:"path" yaml:"path"`
	Args []string `json:"args" yaml:"args"`
	Envs []string `json:"envs" yaml:"envs"`
}

type NetworkCalls struct {
	Protocol    string `json:"protocol" yaml:"protocol"`
	Port        uint16 `json:"port" yaml:"port"`
	DstEndpoint string `json:"dstEndpoint" yaml:"dstEndpoint"`
}

type NetworkActivity struct {
	Incoming []NetworkCalls `json:"incoming" yaml:"incoming"`
	Outgoing []NetworkCalls `json:"outgoing" yaml:"outgoing"`
}

type OpenCalls struct {
	Path  string   `json:"path" yaml:"path"`
	Flags []string `json:"flags" yaml:"flags"`
}

type CapabilitiesCalls struct {
	Capabilities []string `json:"caps" yaml:"caps"`
	Syscall      string   `json:"syscall" yaml:"syscall"`
}

type DnsCalls struct {
	DnsName   string   `json:"dnsName" yaml:"dnsName"`
	Addresses []string `json:"addresses" yaml:"addresses"`
}

type ContainerProfile struct {
	Name            string              `json:"name" yaml:"name"`
	Execs           []ExecCalls         `json:"execs" yaml:"execs"`
	Opens           []OpenCalls         `json:"opens" yaml:"opens"`
	NetworkActivity NetworkActivity     `json:"networkActivity" yaml:"networkActivity"`
	Capabilities    []CapabilitiesCalls `json:"capabilities" yaml:"capabilities"`
	Dns             []DnsCalls          `json:"dns" yaml:"dns"`
	SysCalls        []string            `json:"syscalls" yaml:"syscalls"`
}

type ApplicationProfile struct {
	Name       string             `json:"name" yaml:"name"`
	Containers []ContainerProfile `json:"containers" yaml:"containers"`
}

type ApplicationProfiles map[string]ApplicationProfile
