package engine

import (
	"context"
	"net/http"
	_ "net/http/pprof"
	"runtime"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/armosec/kubecop/pkg/engine/rule"
	"github.com/armosec/kubecop/pkg/rulebindingstore"
	"github.com/armosec/kubecop/pkg/scan"
	"github.com/kubescape/kapprofiler/pkg/collector"
	"github.com/kubescape/kapprofiler/pkg/tracing"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// Event loader

// EventLoader struct holds the configuration for the event loading mechanism
type EventLoader struct {
	callbackFunc func()
	frequency    int
	duration     time.Duration
	ticker       *time.Ticker
	stopChan     chan bool
	externalWait chan bool
}

// NewEventLoader creates a new EventLoader with the given parameters
func NewEventLoader(callbackFunc func(), frequency int, durationInMinutes int) *EventLoader {
	return &EventLoader{
		callbackFunc: callbackFunc,
		frequency:    frequency,
		duration:     time.Duration(durationInMinutes) * time.Minute,
		stopChan:     make(chan bool),
		externalWait: make(chan bool),
	}
}

// Start begins the event loading process
func (e *EventLoader) Start() {
	e.ticker = time.NewTicker(time.Second / time.Duration(e.frequency))
	go func() {
		for {
			select {
			case <-e.ticker.C:
				e.callbackFunc()
			case <-e.stopChan:
				e.ticker.Stop()
				e.externalWait <- true
				return
			}
		}
	}()
	time.AfterFunc(e.duration, func() {
		e.stopChan <- true
	})
}

func (e *EventLoader) Wait() {
	<-e.externalWait
}

// Mocks

type MockExporter struct {
	Alerts []rule.RuleFailure
}

func (m *MockExporter) SendRuleAlert(failedRule rule.RuleFailure) {
	m.Alerts = append(m.Alerts, failedRule)
}

func (m *MockExporter) SendMalwareAlert(failedRule scan.MalwareDescription) {
}

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

func (m *MockAppProfileAccess) GetCapabilities() (*[]collector.CapabilitiesCalls, error) {
	return &m.Capabilities, nil
}

func (m *MockAppProfileAccess) GetDNS() (*[]collector.DnsCalls, error) {
	return &m.Dns, nil
}

// ApplicationProfileCacheMock is a mock implementation of ApplicationProfileCache.
type ApplicationProfileCacheMock struct {
	// MockAppProfileAccess is a mock implementation of SingleApplicationProfileAccess.
	MockAppProfileAccess *MockAppProfileAccess
}

// NewApplicationProfileCacheMock creates a new instance of ApplicationProfileCacheMock.
func NewApplicationProfileCacheMock(m *MockAppProfileAccess) *ApplicationProfileCacheMock {
	if m == nil {
		m = &MockAppProfileAccess{}
	}
	return &ApplicationProfileCacheMock{MockAppProfileAccess: m}
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
	return apc.MockAppProfileAccess, nil
}

func TestNewEngine(t *testing.T) {
	// Create a new engine
	e := NewEngine(nil, nil, nil, nil, 0, "localhost")
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
	e := NewEngine(fakeclientset, NewApplicationProfileCacheMock(nil), nil, &MockExporter{}, 0, "localhost")
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

func TestEngine_LoadEngineWithEvents(t *testing.T) {
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

	// Create a mock application profile
	mockAppProfile := &MockAppProfileAccess{
		Execs: []collector.ExecCalls{
			{
				Path: "test",
				Args: []string{"test"},
				Envs: []string{"test"},
			},
		},
		OpenCalls: []collector.OpenCalls{
			{
				Path:  "test",
				Flags: []string{"O_RDONLY"},
			},
		},
		Syscalls: []string{},
		Capabilities: []collector.CapabilitiesCalls{
			{
				Syscall:      "test",
				Capabilities: []string{"test"},
			},
		},
		Dns: []collector.DnsCalls{
			{
				DnsName:   "test",
				Addresses: []string{"test"},
			},
		},
	}

	mockExporter := MockExporter{}

	// Create a new engine
	e := NewEngine(fakeclientset, NewApplicationProfileCacheMock(mockAppProfile), nil, &mockExporter, 0, "localhost")
	e.SetGetRulesForPodFunc(func(podName, namespace string) ([]rulebindingstore.RuntimeAlertRuleBindingRule, error) {
		// Get all rules
		var allRules []rulebindingstore.RuntimeAlertRuleBindingRule
		for _, rule := range rule.GetAllRuleDescriptors() {
			allRules = append(allRules, rulebindingstore.RuntimeAlertRuleBindingRule{
				RuleName: rule.Name,
				RuleID:   rule.ID,
				RuleTags: rule.Tags,
			})
		}
		return allRules, nil
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

	// Call exec event method
	e.SendExecveEvent(&tracing.ExecveEvent{
		GeneralEvent: tracing.GeneralEvent{
			ContainerID: "test",
			Namespace:   "test",
			PodName:     "test",
		},
		PathName: "test",
		Args:     []string{"test"},
		Env:      []string{"test"},
	})
	// Sleep for 100 millisecond to allow the event to be processed
	time.Sleep(100 * time.Millisecond)

	if len(mockExporter.Alerts) != 0 {
		t.Errorf("Expected alerts to be 0, got %v", len(mockExporter.Alerts))
		return
	}

	// Call exec event method with a different path
	e.SendExecveEvent(&tracing.ExecveEvent{
		GeneralEvent: tracing.GeneralEvent{
			ContainerID: "test",
			Namespace:   "test",
			PodName:     "test",
		},
		PathName: "test2",
		Args:     []string{"test"},
		Env:      []string{"test"},
	})
	// Sleep for 100 millisecond to allow the event to be processed
	time.Sleep(100 * time.Millisecond)

	if len(mockExporter.Alerts) != 1 {
		t.Errorf("Expected alerts to be 1, got %v", len(mockExporter.Alerts))
		return
	}

	timeToLoadInMinutes := 1

	execEventLoader := NewEventLoader(func() {
		// Call exec event method
		e.SendExecveEvent(&tracing.ExecveEvent{
			GeneralEvent: tracing.GeneralEvent{
				ContainerID: "test",
				Namespace:   "test",
				PodName:     "test",
			},
			PathName: "test",
			Args:     []string{"test"},
			Env:      []string{"test"},
		})
	}, 20, timeToLoadInMinutes)

	openEventLoader := NewEventLoader(func() {
		// Call open event method
		e.SendOpenEvent(&tracing.OpenEvent{
			GeneralEvent: tracing.GeneralEvent{
				ContainerID: "test",
				Namespace:   "test",
				PodName:     "test",
			},
			PathName: "test",
			Flags:    []string{"O_RDONLY"},
		})
	}, 4000, timeToLoadInMinutes)

	capabilityEventLoader := NewEventLoader(func() {
		// Call capability event method
		e.SendCapabilitiesEvent(&tracing.CapabilitiesEvent{
			GeneralEvent: tracing.GeneralEvent{
				ContainerID: "test",
				Namespace:   "test",
				PodName:     "test",
			},
			Syscall:        "test",
			CapabilityName: "test",
		})
	}, 2000, timeToLoadInMinutes)

	dnsEventLoader := NewEventLoader(func() {
		// Call dns event method
		e.SendDnsEvent(&tracing.DnsEvent{
			GeneralEvent: tracing.GeneralEvent{
				ContainerID: "test",
				Namespace:   "test",
				PodName:     "test",
			},
			DnsName:   "test",
			Addresses: []string{"test"},
		})
	}, 300, timeToLoadInMinutes)

	netEventLoader := NewEventLoader(func() {
		// Call network event method
		e.SendNetworkEvent(&tracing.NetworkEvent{
			GeneralEvent: tracing.GeneralEvent{
				ContainerID: "test",
				Namespace:   "test",
				PodName:     "test",
			},
			PacketType:  "test",
			Protocol:    "test",
			Port:        0,
			DstEndpoint: "test",
		})
	}, 600, timeToLoadInMinutes)

	// Start pprof server
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	execEventLoader.Start()
	openEventLoader.Start()
	capabilityEventLoader.Start()
	dnsEventLoader.Start()
	netEventLoader.Start()

	// Print every minute the memory usage of the process
	i := 0
	for {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		log.Printf("-------------------")
		log.Printf("Alloc = %v MiB", bToMb(m.Alloc))
		log.Printf("Sys = %v MiB", bToMb(m.Sys))
		log.Printf("LiveObjects = %d", m.Mallocs-m.Frees)
		log.Printf("NumGC = %v\n", m.NumGC)
		log.Printf("Alerts = %v\n", len(mockExporter.Alerts))
		time.Sleep(1 * time.Minute)
		i++
		if i == timeToLoadInMinutes {
			break
		}
	}

	execEventLoader.Wait()
	openEventLoader.Wait()
	capabilityEventLoader.Wait()
	dnsEventLoader.Wait()
	netEventLoader.Wait()

}

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}
