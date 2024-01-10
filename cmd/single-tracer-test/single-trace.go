package main

import (
	"os"
	"os/signal"
	"syscall"

	"net/http"
	_ "net/http/pprof"

	log "github.com/sirupsen/logrus"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection/networktracer"
	tracernetwork "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/tracer"
	tracernetworktype "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

var callbackCount int64

func networkEventCallback(event *tracernetworktype.Event) {
	if event.Type == eventtypes.NORMAL {
		callbackCount++
		if callbackCount%100000 == 0 {
			log.Printf("callbackCount: %d\n", callbackCount)
		}
	}
}

func main() {

	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	host.Init(host.Config{AutoMountFilesystems: true})

	// Use container collection to get notified for new containers
	containerCollection := &containercollection.ContainerCollection{}

	// Create a tracer collection instance
	tracerCollection, err := tracercollection.NewTracerCollection(containerCollection)
	if err != nil {
		log.Fatalf("Failed to create tracer collection: %v\n", err)
	}

	// Define the different options for the container collection instance
	opts := []containercollection.ContainerCollectionOption{
		containercollection.WithTracerCollection(tracerCollection),

		// Get containers created with runc
		containercollection.WithRuncFanotify(),

		// Get containers created with docker
		containercollection.WithCgroupEnrichment(),

		// Enrich events with Linux namespaces information, it is needed for per container filtering
		containercollection.WithLinuxNamespaceEnrichment(),
	}

	// Initialize the container collection
	if err := containerCollection.Initialize(opts...); err != nil {
		log.Fatalf("failed to initialize container collection: %s\n", err)
	}

	containerSelector := containercollection.ContainerSelector{}
	if err := tracerCollection.AddTracer("networkTraceName", containerSelector); err != nil {
		log.Fatalf("error adding tracer: %v\n", err)
	}

	tracerNetwork, err := tracernetwork.NewTracer()
	if err != nil {
		log.Printf("error creating tracer: %s\n", err)
	}
	tracerNetwork.SetEventHandler(networkEventCallback)

	config := &networktracer.ConnectToContainerCollectionConfig[tracernetworktype.Event]{
		Tracer:   tracerNetwork,
		Resolver: containerCollection,
		Selector: containerSelector,
		Base:     tracernetworktype.Base,
	}

	_, err = networktracer.ConnectToContainerCollection(config)

	if err != nil {
		log.Fatalf("error creating tracer: %s\n", err)
	}

	// Wait for shutdown signal
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)
	<-shutdown
	log.Println("Shutting down...")

}
