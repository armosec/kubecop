package ebpf

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf/rlimit"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Global variables
var NodeName string
var k8sConfig *rest.Config

func checkKubernetesConnection() (*rest.Config, error) {
	// Check if the Kubernetes cluster is reachable
	// Load the Kubernetes configuration from the default location
	config, err := clientcmd.BuildConfigFromFlags("", clientcmd.RecommendedHomeFile)
	if err != nil {
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, err
		}
	}

	// Create a Kubernetes client
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Printf("Failed to create Kubernetes client: %v\n", err)
		return nil, err
	}

	// Send a request to the API server to check if it's reachable
	_, err = clientset.CoreV1().Pods("default").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		log.Printf("Failed to communicate with Kubernetes API server: %v\n", err)
		return nil, err
	}

	return config, nil
}

func serviceInitNChecks() error {
	// Raise the rlimit for memlock to the maximum allowed (eBPF needs it)
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	// Check Kubernetes cluster connection
	config, err := checkKubernetesConnection()
	if err != nil {
		return err
	}
	k8sConfig = config

	// Get Node name from environment variable
	if nodeName := os.Getenv("NODE_NAME"); nodeName == "" {
		return fmt.Errorf("NODE_NAME environment variable not set")
	} else {
		NodeName = nodeName
	}

	return nil
}
