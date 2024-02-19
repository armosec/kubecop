package approfilecache

import (
	"context"
	"log"
	"testing"
	"time"

	"github.com/kubescape/kapprofiler/pkg/collector"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dfake "k8s.io/client-go/dynamic/fake"
)

func TestCacheBasicExists(t *testing.T) {
	// ApplicationProfile
	appProfile := collector.ApplicationProfile{
		ObjectMeta: v1.ObjectMeta{
			Name:      "deployment-nginx",
			Namespace: "default",
			Labels: map[string]string{
				"kapprofiler.kubescape.io/final": "true",
			},
		},
		Spec: collector.ApplicationProfileSpec{
			Containers: []collector.ContainerProfile{
				{
					Name: "nginx",
					Execs: []collector.ExecCalls{
						{
							Path: "/bin/bash",
							Args: []string{"-c", "echo hello"},
							Envs: []string{"PATH=/bin"},
						},
					},
				},
			},
		},
	}

	// Convert application profile to unstructured
	appProfileUnstructured, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&appProfile)
	if err != nil {
		t.Errorf("Failed to convert application profile to unstructured: %v", err)
		return
	}

	// Setup your test if needed
	dynamicClient := dfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		collector.AppProfileGvr: collector.ApplicationProfileKind + "List",
		schema.GroupVersionResource{
			Group:    "",
			Version:  "v1",
			Resource: "pods",
		}: "PodList",
		schema.GroupVersionResource{
			Group:    "",
			Version:  "v1",
			Resource: "namespaces",
		}: "NamespaceList",
	})

	// Add the ApplicationProfile to the fake dynamic client
	_, err = dynamicClient.Resource(collector.AppProfileGvr).Namespace("default").Create(context.Background(), &unstructured.Unstructured{Object: appProfileUnstructured}, v1.CreateOptions{})
	if err != nil {
		t.Errorf("Failed to create application profile: %v", err)
		return
	}

	cache, err := NewApplicationProfileK8sCache(dynamicClient, "")
	if err != nil {
		t.Errorf("Failed to create cache: %v", err)
		return
	}
	defer cache.Destroy()

	// Load a container profile
	err = cache.LoadApplicationProfile("default", "pod", "nginx-aaaaa-bbbb", "deployment", "nginx", "nginx", "00000000000000000000000000000000", false)
	if err != nil {
		t.Errorf("Failed to load container profile: %v", err)
		return
	}

	// Check if the container profile is in the cache
	_, err = cache.GetApplicationProfileAccess("nginx", "00000000000000000000000000000000")
	if err != nil {
		t.Errorf("Failed to get container profile: %v", err)
		return
	}
}

func TestCacheBasicAnticipateProfile(t *testing.T) {
	// ApplicationProfile
	appProfile := collector.ApplicationProfile{
		ObjectMeta: v1.ObjectMeta{
			Name:      "deployment-nginx",
			Namespace: "default",
			Labels: map[string]string{
				"kapprofiler.kubescape.io/final": "true",
			},
		},
		Spec: collector.ApplicationProfileSpec{
			Containers: []collector.ContainerProfile{
				{
					Name: "nginx",
					Execs: []collector.ExecCalls{
						{
							Path: "/bin/bash",
							Args: []string{"-c", "echo hello"},
							Envs: []string{"PATH=/bin"},
						},
					},
				},
			},
		},
	}

	// Convert application profile to unstructured
	appProfileUnstructured, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&appProfile)
	if err != nil {
		t.Errorf("Failed to convert application profile to unstructured: %v", err)
		return
	}

	// Setup your test if needed
	dynamicClient := dfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		collector.AppProfileGvr: collector.ApplicationProfileKind + "List",
		schema.GroupVersionResource{
			Group:    "",
			Version:  "v1",
			Resource: "pods",
		}: "PodList",
		schema.GroupVersionResource{
			Group:    "",
			Version:  "v1",
			Resource: "namespaces",
		}: "NamespaceList",
	})

	cache, err := NewApplicationProfileK8sCache(dynamicClient, "")
	if err != nil {
		t.Errorf("Failed to create cache: %v", err)
		return
	}
	defer cache.Destroy()

	// Create Anticipation a container profile
	err = cache.AnticipateApplicationProfile("default", "pod", "nginx-aaaaa-bbbb", "deployment", "nginx", "nginx", "00000000000000000000000000000000", false)
	if err != nil {
		t.Errorf("Failed to anticipate container profile: %v", err)
		return
	}

	// Add the ApplicationProfile to the fake dynamic client
	_, err = dynamicClient.Resource(collector.AppProfileGvr).Namespace("default").Create(context.Background(), &unstructured.Unstructured{Object: appProfileUnstructured}, v1.CreateOptions{})
	if err != nil {
		t.Errorf("Failed to create application profile: %v", err)
		return
	}

	log.Printf("Waiting for cache to be updated")

	// Wait a second for the cache to be updated
	time.Sleep(1 * time.Second)

	log.Printf("Cache: %v", cache.cache)

	// Check if the container profile is in the cache
	_, err = cache.GetApplicationProfileAccess("nginx", "00000000000000000000000000000000")
	if err != nil {
		t.Errorf("Failed to get container profile: %v", err)
		return
	}
}
