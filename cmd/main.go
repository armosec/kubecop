package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"net/http"
	_ "net/http/pprof"

	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/armosec/kubecop/pkg/engine"
	"github.com/armosec/kubecop/pkg/exporters"
	"github.com/armosec/kubecop/pkg/rulebindingstore"
	"github.com/cilium/ebpf/rlimit"
	"github.com/kubescape/kapprofiler/pkg/collector"
	reconcilercontroller "github.com/kubescape/kapprofiler/pkg/controller"
	"github.com/kubescape/kapprofiler/pkg/eventsink"
	"github.com/kubescape/kapprofiler/pkg/tracing"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Global variables
var NodeName string
var k8sConfig *rest.Config
var FinalizationDurationInSeconds int64 = 120
var SamplingIntervalInSeconds int64 = 60

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

	// Get finalization time from environment variable
	if finalizationDuration := os.Getenv("FINALIZATION_DURATION"); finalizationDuration != "" {
		if finalizationTimeInt, err := parseTimeToSeconds(finalizationDuration); err != nil {
			return fmt.Errorf("FINALIZATION_DURATION environment variable is not in format <number><unit> like 20s, 5m, 1h")
		} else {
			FinalizationDurationInSeconds = int64(finalizationTimeInt)
		}
	}

	// Get sampling interval from environment variable
	if samplingInterval := os.Getenv("SAMPLING_INTERVAL"); samplingInterval != "" {
		if samplingIntervalInt, err := parseTimeToSeconds(samplingInterval); err != nil {
			return fmt.Errorf("SAMPLING_INTERVAL environment variable is not in format <number><unit> like 20s, 5m, 1h")
		} else {
			SamplingIntervalInSeconds = int64(samplingIntervalInt)
		}
	}

	return nil
}

func main() {
	// Start the pprof server if _PPROF_SERVER environment variable is set
	if os.Getenv("_PPROF_SERVER") != "" {
		go func() {
			log.Println(http.ListenAndServe("localhost:6060", nil))
		}()
	}

	// Initialize the service backend
	if err := serviceInitNChecks(); err != nil {
		log.Fatalf("Failed to initialize service: %v\n", err)
	}

	// TODO: support exporters config from file/crd
	exporters.InitExporters(exporters.ExportersConfig{})

	// Create tracer (without sink for now)
	tracer := tracing.NewTracer(NodeName, k8sConfig, []tracing.EventSink{}, false)
	// Create application profile cache
	appProfileCache, err := approfilecache.NewApplicationProfileK8sCache(k8sConfig)
	if err != nil {
		log.Fatalf("Failed to create application profile cache: %v\n", err)
	}
	defer appProfileCache.Destroy()

	//////////////////////////////////////////////////////////////////////////////
	// Fire up the recording subsystem

	eventSink, err := eventsink.NewEventSink("", false)
	if err != nil {
		log.Fatalf("Failed to create event sink: %v\n", err)
	}

	// Start the event sink
	if err := eventSink.Start(); err != nil {
		log.Fatalf("Failed to start event sink: %v\n", err)
	}
	defer eventSink.Stop()

	// Start the collector manager
	collectorManagerConfig := &collector.CollectorManagerConfig{
		EventSink:      eventSink,
		Tracer:         tracer,
		Interval:       uint64(SamplingIntervalInSeconds),
		FinalizeTime:   uint64(FinalizationDurationInSeconds),
		K8sConfig:      k8sConfig,
		RecordStrategy: collector.RecordStrategyOnlyIfNotExists,
		NodeName:       NodeName,
	}
	cm, err := collector.StartCollectorManager(collectorManagerConfig)
	if err != nil {
		log.Fatalf("Failed to start collector manager: %v\n", err)
	}
	defer cm.StopCollectorManager()

	// Last but not least, start the reconciler controller
	appProfileReconcilerController := reconcilercontroller.NewController(k8sConfig)
	appProfileReconcilerController.StartController()
	defer appProfileReconcilerController.StopController()

	//////////////////////////////////////////////////////////////////////////////
	// Recording subsystem is ready, start the rule engine

	// Create Kubernetes clientset from the configuration
	clientset, err := kubernetes.NewForConfig(k8sConfig)
	if err != nil {
		log.Fatalf("Failed to create Kubernetes client: %v\n", err)
	}
	dynamicClient, err := dynamic.NewForConfig(k8sConfig)
	if err != nil {
		log.Fatalf("Failed to create Kubernetes dynamic client: %v\n", err)
	}

	// Create the "Rule Engine" and start it
	engine := engine.NewEngine(clientset, appProfileCache, tracer, 4, NodeName)

	// Create the rule binding store and start it
	ruleBindingStore, err := rulebindingstore.NewRuleBindingK8sStore(dynamicClient, clientset.CoreV1(), NodeName)
	if err != nil {
		log.Fatalf("Failed to create rule binding store: %v\n", err)
	}
	defer ruleBindingStore.Destroy()
	// set mutual callbacks between engine and rulebindingstore
	engine.SetGetRulesForPodFunc(ruleBindingStore.GetRulesForPod)
	ruleBindingStore.SetRuleBindingChangedHandlers([]rulebindingstore.RuleBindingChangedHandler{engine.OnRuleBindingChanged})

	// Add the engine to the tracer
	tracer.AddContainerActivityListener(engine)
	defer tracer.RemoveContainerActivityListener(engine)

	tracer.AddEventSink(engine)
	defer tracer.RemoveEventSink(engine)
	tracer.AddEventSink(eventSink)
	defer tracer.RemoveEventSink(eventSink)

	// Start the tracer
	if err := tracer.Start(); err != nil {
		log.Fatalf("Failed to start tracer: %v\n", err)
	}
	log.Printf("Tracer started")

	// Start prometheus metrics server
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		http.ListenAndServe(":9090", nil)
	}()

	// Wait for shutdown signal
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)
	<-shutdown
	log.Println("Shutting down...")

	// Stop HTTP server

	// Stop the tracer
	tracer.Stop()

	// Exit with success
	os.Exit(0)
}

func parseTimeToSeconds(timeStr string) (int, error) {
	if len(timeStr) < 2 {
		return 0, fmt.Errorf("invalid time format")
	}

	// Get the time unit and the number part
	unit := timeStr[len(timeStr)-1:]
	numberStr := timeStr[:len(timeStr)-1]

	// Convert the number part to an integer
	number, err := strconv.Atoi(numberStr)
	if err != nil {
		return 0, err
	}

	// Convert according to the unit
	switch unit {
	case "s":
		return number, nil
	case "m":
		return number * 60, nil
	case "h":
		return number * 3600, nil
	default:
		return 0, fmt.Errorf("unknown time unit: %s", unit)
	}
}
