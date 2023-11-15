package rule

import (
	"github.com/kubescape/kapprofiler/pkg/collector"
)

type MockAppProfileAccess struct {
	Execs        []collector.ExecCalls
	Syscalls     []string
	Capabilities []collector.CapabilitiesCalls
	Dns          []collector.DnsCalls
}

func (m *MockAppProfileAccess) GetExecList() (*[]collector.ExecCalls, error) {
	return &m.Execs, nil
}

func (m *MockAppProfileAccess) GetOpenList() (*[]collector.OpenCalls, error) {
	return nil, nil
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
