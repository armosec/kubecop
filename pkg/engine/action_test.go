package engine

import (
	"context"
	"testing"

	"github.com/armosec/kubecop/pkg/engine/rule"
	"github.com/kubescape/kapprofiler/pkg/tracing"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestEngineAction(t *testing.T) {
	fakeClientSet := fake.NewSimpleClientset()
	fakePod, err := fakeClientSet.CoreV1().Pods("default").Create(context.TODO(), &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
	}, metav1.CreateOptions{})

	if err != nil {
		t.Fatal(err)
	}

	e := NewEngine(fakeClientSet, NewApplicationProfileCacheMock(), nil, 0, "localhost")
	defer e.Delete()

	e.Action(
		&rule.R1007CryptoMinersFailure{
			RuleName: "test-rule",
			FailureEvent: &tracing.NetworkEvent{
				GeneralEvent: tracing.GeneralEvent{
					PodName:   fakePod.Name,
					Namespace: fakePod.Namespace,
					ProcessDetails: tracing.ProcessDetails{
						Pid:  1234,
						Ppid: 5678,
					},
				},
				PacketType:  "OUTGOING",
				Protocol:    "TCP",
				Port:        3333,
				DstEndpoint: "1.1.1.1",
			},
		},
		rule.KillPodAction,
	)

	_, err = fakeClientSet.CoreV1().Pods("default").Get(context.Background(), "test-pod", metav1.GetOptions{})
	if err == nil {
		t.Errorf("Expected pod to be deleted")
		t.Fatal(err)
	}
}
