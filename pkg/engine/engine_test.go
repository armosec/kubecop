package engine

import (
	"context"
	"testing"
	"time"

	"github.com/kubescape/kapprofiler/pkg/tracing"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestNewEngine(t *testing.T) {
	// Create a new engine
	e := NewEngine(nil, nil, 0)
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
	e := NewEngine(fakeclientset, nil, 0)
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
