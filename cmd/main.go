package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"net/http"
	_ "net/http/pprof"

	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/armosec/kubecop/pkg/engine"
	"github.com/armosec/kubecop/pkg/exporters"
	"github.com/armosec/kubecop/pkg/rulebindingstore"
	scan "github.com/armosec/kubecop/pkg/scan/clamav"
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
var dynamicClientGlobal dynamic.Interface
var FinalizationDurationInSeconds int64 = 120
var FinalizationJitterInSeconds int64 = 30
var SamplingIntervalInSeconds int64 = 60
var ClamAVRetryDelay time.Duration = 10 * time.Second
var ClamAVMaxRetries int = 5

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

func serviceInitNChecks(modeEbpf bool) error {
	// Raise the rlimit for memlock to the maximum allowed (eBPF needs it)
	if modeEbpf {
		if err := rlimit.RemoveMemlock(); err != nil {
			return err
		}
	}

	// Check Kubernetes cluster connection
	config, err := checkKubernetesConnection()
	if err != nil {
		return err
	}
	k8sConfig = config

	// Create Dyanmic client
	dynamicClient, err := dynamic.NewForConfig(k8sConfig)
	if err != nil {
		return err
	}
	dynamicClientGlobal = dynamicClient

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

	// Get finalization jitter from environment variable
	if finalizationJitter := os.Getenv("FINALIZATION_JITTER"); finalizationJitter != "" {
		if finalizationJitterInt, err := parseTimeToSeconds(finalizationJitter); err != nil {
			return fmt.Errorf("FINALIZATION_JITTER environment variable is not in format <number><unit> like 20s, 5m, 1h")
		} else {
			FinalizationJitterInSeconds = int64(finalizationJitterInt)
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
	// Set log level
	logLevel := os.Getenv("DEBUG")
	if logLevel == "" {
		logLevel = "info"
	} else {
		logLevel = "debug"
	}

	if level, err := log.ParseLevel(logLevel); err != nil {
		log.Fatalf("Failed to parse log level: %v\n", err)
	} else {
		log.SetLevel(level)
	}

	// Parse command line arguments to check which mode to run in
	controllerMode := false
	nodeAgentMode := false
	storeNamespace := ""

	for _, arg := range os.Args[1:] {
		switch arg {
		case "--mode-controller":
			// Run in controller mode
			controllerMode = true
			log.Printf("Running in controller mode")
		case "--mode-node-agent":
			// Run in node agent mode
			nodeAgentMode = true
			log.Printf("Running in node agent mode")
		default:
			log.Fatalf("Unknown command line argument: %s", arg)
		}
	}

	if ns := os.Getenv("STORE_NAMESPACE"); ns != "" {
		storeNamespace = ns
	}

	if !controllerMode && !nodeAgentMode {
		controllerMode = true
		nodeAgentMode = true
		log.Printf("Running in both controller and node agent mode")
	}

	// Start the pprof server if _PPROF_SERVER environment variable is set
	if os.Getenv("_PPROF_SERVER") != "" {
		go func() {
			log.Println(http.ListenAndServe("localhost:6060", nil))
		}()
	}

	// Initialize the service backend
	if err := serviceInitNChecks(nodeAgentMode); err != nil {
		log.Fatalf("Failed to initialize service: %v\n", err)
	}

	if nodeAgentMode {
		// TODO: support exporters config from file/crd
		exporterBus := exporters.InitExporters(exporters.ExportersConfig{})
		// Create tracer (without sink for now)
		tracer := tracing.NewTracer(NodeName, k8sConfig, []tracing.EventSink{}, false)
		// Create application profile cache
		appProfileCache, err := approfilecache.NewApplicationProfileK8sCache(dynamicClientGlobal, storeNamespace)
		if err != nil {
			log.Fatalf("Failed to create application profile cache: %v\n", err)
		}
		defer appProfileCache.Destroy()

		//////////////////////////////////////////////////////////////////////////////
		// Fire up the recording subsystem

		eventSink, err := eventsink.NewEventSink("", true)
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
			FinalizeJitter: uint64(FinalizationJitterInSeconds),
			K8sConfig:      k8sConfig,
			RecordStrategy: collector.RecordStrategyOnlyIfNotExists,
			NodeName:       NodeName,
			StoreNamespace: storeNamespace,
			OnError:        func(err error) { log.Fatalf("Collector manager watcher error: %v\n", err) },
		}
		cm, err := collector.StartCollectorManager(collectorManagerConfig)
		if err != nil {
			log.Fatalf("Failed to start collector manager: %v\n", err)
		}
		defer cm.StopCollectorManager()

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
		engine := engine.NewEngine(clientset, appProfileCache, tracer, &exporterBus, 4, NodeName)

		// Create the rule binding store and start it
		ruleBindingStore, err := rulebindingstore.NewRuleBindingK8sStore(dynamicClient, clientset.CoreV1(), NodeName, storeNamespace)
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

		// Start the ClamAV scanner
		clamavConfig := scan.ClamAVConfig{
			Host:             os.Getenv("CLAMAV_HOST"),
			Port:             os.Getenv("CLAMAV_PORT"),
			ScanInterval:     os.Getenv("CLAMAV_SCAN_INTERVAL"),
			RetryDelay:       ClamAVRetryDelay,
			MaxRetries:       ClamAVMaxRetries,
			ExporterBus:      &exporterBus,
			KubernetesClient: clientset,
		}

		clamavConfigured := false
		var clamav *scan.ClamAV
		clamAVContext, cancel := context.WithCancel(context.Background())
		defer cancel()

		if clamavConfig.Host != "" && clamavConfig.Port != "" && clamavConfig.ScanInterval != "" {
			clamav = scan.NewClamAV(clamavConfig)

			// Check if we can connect to ClamAV - Retry every 10 seconds until we can connect.
			retryCount := 0

			for retryCount < clamavConfig.MaxRetries {
				if err := clamav.Ping(); err != nil {
					retryCount++
					log.Printf("Failed to connect to ClamAV: %v\n", err)
					log.Printf("Retrying in %d seconds...\n", clamavConfig.RetryDelay/time.Second)
					// Wait before retrying.
					time.Sleep(clamavConfig.RetryDelay)
					continue
				}

				log.Printf("Connected to ClamAV\n")
				break
			}

			// Start the ClamAV scanner
			if retryCount == clamavConfig.MaxRetries {
				log.Fatalf("Failed to connect to ClamAV after %d retries. Exiting...\n", clamavConfig.MaxRetries)
			} else {
				// Add ClamAV to the tracer
				tracer.AddContainerActivityListener(clamav)
				defer tracer.RemoveContainerActivityListener(clamav)
				clamavConfigured = true
			}
		}

		tracer.AddEventSink(engine)
		defer tracer.RemoveEventSink(engine)
		tracer.AddEventSink(eventSink)
		defer tracer.RemoveEventSink(eventSink)

		// Start the tracer
		if err := tracer.Start(); err != nil {
			log.Fatalf("Failed to start tracer: %v\n", err)
		}
		defer tracer.Stop()
		log.Printf("Tracer started")

		// Start the clamav scanner (Avoid race).
		if clamavConfigured {
			go clamav.StartInfiniteScan(clamAVContext, os.Getenv("CLAMAV_SCAN_PATH"))
		}
	}

	if controllerMode {
		// Last but not least, start the reconciler controller
		appProfileReconcilerController := reconcilercontroller.NewController(k8sConfig, storeNamespace, func(err error) {
			log.Fatalf("Reconciler controller watcher error: %v\n", err)
		})
		appProfileReconcilerController.StartController()
		defer appProfileReconcilerController.StopController()
	}

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
