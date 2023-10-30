package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/armosec/kubecop/pkg/appprofilecache"
	"github.com/armosec/kubecop/pkg/engine"
	"github.com/cilium/ebpf/rlimit"
	"github.com/kubescape/kapprofiler/pkg/tracing"
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

func main() {
	// Initialize the service backend
	if err := serviceInitNChecks(); err != nil {
		log.Fatalf("Failed to initialize service: %v\n", err)
	}

	// Create tracer (without sink for now)
	tracer := tracing.NewTracer(NodeName, k8sConfig, []tracing.EventSink{}, false)

	// Create application profile cache
	appProfileCache, err := appprofilecache.NewApplicationProfileK8sCache(k8sConfig)
	if err != nil {
		log.Fatalf("Failed to create application profile cache: %v\n", err)
	}

	// TODO: here will be the initialization of the recording subsystem

	// Create the "Rule Engine" and start it
	engine := engine.NewEngine(ebpfManager.ApplicationProfiles) // The profiles will be updated dynamically by the ebpf collector.
	go engine.Start()

	// Wait for shutdown signal
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)
	<-shutdown
	log.Println("Shutting down...")

	ebpfManager.StopEventCollection()

	// Exit with success
	os.Exit(0)
}
