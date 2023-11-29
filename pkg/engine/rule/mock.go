package rule

import (
	"github.com/kubescape/kapprofiler/pkg/collector"
	corev1 "k8s.io/api/core/v1"
)

type EngineAccessMock struct {
}

func (e *EngineAccessMock) GetPodSpec(podName, namespace, containerID string) (*corev1.PodSpec, error) {
	podSpec := corev1.PodSpec{}
	podSpec.Containers = []corev1.Container{
		{
			Name:  "test",
			Image: "test",
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      "test",
					MountPath: "/var/test1",
				},
				{
					Name:      "test2",
					MountPath: "/var/test2",
					SubPath:   "test2",
				},
			},
		},
	}

	return &podSpec, nil
}

type MockAppProfileAccess struct {
	Execs        []collector.ExecCalls
	OpenCalls    []collector.OpenCalls
	Syscalls     []string
	Capabilities []collector.CapabilitiesCalls
	Dns          []collector.DnsCalls
}

func (m *MockAppProfileAccess) GetExecList() (*[]collector.ExecCalls, error) {
	return &m.Execs, nil
}

func (m *MockAppProfileAccess) GetOpenList() (*[]collector.OpenCalls, error) {
	return &m.OpenCalls, nil
}

func (m *MockAppProfileAccess) GetNetworkActivity() (*collector.NetworkActivity, error) {
	return nil, nil
}

func (m *MockAppProfileAccess) GetSystemCalls() ([]string, error) {
	return m.Syscalls, nil
}

func (m *MockAppProfileAccess) GetCapabilities() ([]collector.CapabilitiesCalls, error) {
	return m.Capabilities, nil
}

func (m *MockAppProfileAccess) GetDNS() (*[]collector.DnsCalls, error) {
	return &m.Dns, nil
}
