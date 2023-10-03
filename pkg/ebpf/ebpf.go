package ebpf

import (
	"log"

	"github.com/armosec/kubecop/pkg/ebpf/collector"
	"github.com/kubescape/kapprofiler/pkg/eventsink"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

type EbpfManager struct {
	ApplicationProfiles map[string]collector.ApplicationProfile
	eventSink           *eventsink.EventSink
	tracer              *tracing.Tracer
	collectorManager    *collector.CollectorManager

	interval uint64
}

func NewEbpfManager(interval uint64) *EbpfManager {
	return &EbpfManager{
		ApplicationProfiles: make(map[string]collector.ApplicationProfile),
		interval:            interval,
	}
}

func (ebpfManager *EbpfManager) StartEventCollection() {
	// Initialize the service
	if err := serviceInitNChecks(); err != nil {
		log.Fatalf("Failed to initialize service: %v\n", err)
	}

	// Create the event sink
	eventSink, err := eventsink.NewEventSink("")
	if err != nil {
		log.Fatalf("Failed to create event sink: %v\n", err)
	}

	ebpfManager.eventSink = eventSink

	// Start the event sink
	if err := ebpfManager.eventSink.Start(); err != nil {
		log.Fatalf("Failed to start event sink: %v\n", err)
	}

	// Create the tracer
	tracer := tracing.NewTracer(NodeName, k8sConfig, ebpfManager.eventSink, false)
	ebpfManager.tracer = tracer

	// Start the collector manager
	collectorManagerConfig := &collector.CollectorManagerConfig{
		EventSink:           ebpfManager.eventSink,
		Tracer:              ebpfManager.tracer,
		Interval:            ebpfManager.interval,
		K8sConfig:           k8sConfig,
		ApplicationProfiles: ebpfManager.ApplicationProfiles,
	}
	collectorManager, err := collector.StartCollectorManager(collectorManagerConfig)
	if err != nil {
		log.Fatalf("Failed to start collector manager: %v\n", err)
	}
	ebpfManager.collectorManager = collectorManager
	if err != nil {
		log.Fatalf("Failed to start collector manager: %v\n", err)
	}

	// Start the service
	if err := ebpfManager.tracer.Start(); err != nil {
		log.Fatalf("Failed to start service: %v\n", err)
	}
}

func (ebpfManager *EbpfManager) StopEventCollection() {
	ebpfManager.eventSink.Stop()
	ebpfManager.collectorManager.StopCollectorManager()
	ebpfManager.tracer.Stop()
}
