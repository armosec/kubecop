package engine

import (
	"context"
	"testing"
	"time"

	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/armosec/kubecop/pkg/rulebindingstore"
	"github.com/kubescape/kapprofiler/pkg/collector"
	"github.com/kubescape/kapprofiler/pkg/tracing"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// Mocks

type MockAppProfileAccess struct {
	Execs        []collector.ExecCalls
	OpenCalls    []collector.OpenCalls
	Syscalls     []string
	Capabilities []collector.CapabilitiesCalls
	Dns          []collector.DnsCalls
}

func (m *MockAppProfileAccess) GetName() string {
	return "testProfileName"
}

func (m *MockAppProfileAccess) GetNamespace() string {
	return "testProfileNamespace"
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

// ApplicationProfileCacheMock is a mock implementation of ApplicationProfileCache.
type ApplicationProfileCacheMock struct{}

// NewApplicationProfileCacheMock creates a new instance of ApplicationProfileCacheMock.
func NewApplicationProfileCacheMock() *ApplicationProfileCacheMock {
	return &ApplicationProfileCacheMock{}
}

// LoadApplicationProfile mocks loading an application profile to the cache.
func (apc *ApplicationProfileCacheMock) LoadApplicationProfile(namespace, kind, workloadName, ownerKind, ownerName, containerName, containerID string, acceptPartial bool) error {
	// Mock implementation, return nil to simulate success
	return nil
}

// AnticipateApplicationProfile mocks anticipating an application profile to be loaded to the cache.
func (apc *ApplicationProfileCacheMock) AnticipateApplicationProfile(namespace, kind, workloadName, ownerKind, ownerName, containerName, containerID string, acceptPartial bool) error {
	// Mock implementation, return nil to simulate success
	return nil
}

// DeleteApplicationProfile mocks deleting an application profile from the cache.
func (apc *ApplicationProfileCacheMock) DeleteApplicationProfile(containerID string) error {
	// Mock implementation, return nil to simulate success
	return nil
}

// HasApplicationProfile mocks checking if there is an application profile for the given container.
func (apc *ApplicationProfileCacheMock) HasApplicationProfile(namespace, kind, workloadName, containerName string) bool {
	// Mock implementation, return false to indicate the profile is not present
	return false
}

// GetApplicationProfileAccess mocks getting application profile access for the given container.
func (apc *ApplicationProfileCacheMock) GetApplicationProfileAccess(containerName, containerID string) (approfilecache.SingleApplicationProfileAccess, error) {
	// Mock implementation, return a default SingleApplicationProfileAccess and nil for error
	return &MockAppProfileAccess{}, nil
}

func TestNewEngine(t *testing.T) {
	// Create a new engine
	e := NewEngine(nil, nil, nil, 0, "localhost")
	// Assert e is not nil
	if e == nil {
		t.Errorf("Expected e to not be nil")
	}
	defer e.Delete()
}

func TestEngine_ContainerStartStop(t *testing.T) {
	fakeclientset := fake.NewSimpleClientset()

	fakeclientset.CoreV1().Pods("test").Create(context.TODO(), &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test",
			Namespace: "test",
			OwnerReferences: []metav1.OwnerReference{
				{
					Kind: "StatefulSet",
					Name: "testowner",
				},
			},
		},
	}, metav1.CreateOptions{})

	fakeclientset.AppsV1().StatefulSets("test").Create(context.TODO(), &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "testowner",
			Namespace: "test",
		},
	}, metav1.CreateOptions{})

	// Create a new engine
	e := NewEngine(fakeclientset, NewApplicationProfileCacheMock(), nil, 0, "localhost")
	e.SetGetRulesForPodFunc(func(podName, namespace string) ([]rulebindingstore.RuntimeAlertRuleBindingRule, error) {
		return []rulebindingstore.RuntimeAlertRuleBindingRule{{RuleName: "testrule"}}, nil
	})
	// Assert e is not nil
	if e == nil {
		t.Errorf("Expected e to not be nil")
	}
	defer e.Delete()

	e.OnContainerActivityEvent(&tracing.ContainerActivityEvent{
		Activity:      tracing.ContainerActivityEventStart,
		ContainerName: "test",
		ContainerID:   "test",
		PodName:       "test",
		Namespace:     "test",
		NsMntId:       0,
	})

	// Sleep for 1 second
	time.Sleep(1 * time.Second)

	kind, owner, err := e.GetWorkloadOwnerKindAndName(&tracing.GeneralEvent{
		ContainerID: "test",
	})
	if err != nil {
		t.Errorf("Expected err to be nil, got %v", err)
	}
	if kind != "StatefulSet" {
		t.Errorf("Expected owner to be StatefulSet, got %v", owner)
	}
	if owner != "testowner" {
		t.Errorf("Expected kind to be testowner, got %v", kind)
	}

	e.OnContainerActivityEvent(&tracing.ContainerActivityEvent{
		Activity:      tracing.ContainerActivityEventStop,
		ContainerName: "test",
		ContainerID:   "test",
		PodName:       "test",
		Namespace:     "test",
		NsMntId:       0,
	})

}
