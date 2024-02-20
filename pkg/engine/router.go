package engine

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/kubescape/kapprofiler/pkg/tracing"
)

// This function enables prefiltering of events before they are processed by the engine.
func (engine *Engine) eventNeedsProcessing(containerId string, eventType tracing.EventType, event interface{}) bool {
	// TODO - implement
	// check if there are any rules that are bound to this event

	return engine.IsContainerIDInCache(containerId)
}

// submitEventForProcessing submits an event for processing by the engine through the event processing pool.
// This decouples the event fire thread from the event processing thread.
func (engine *Engine) submitEventForProcessing(containerId string, eventType tracing.EventType, event interface{}) {

	if !engine.eventNeedsProcessing(containerId, eventType, event) {
		return
	}

	// Add the event to a working group
	engine.eventProcessingPool.Submit(func() {
		// Convert the event to a generic event
		e, err := convertEventInterfaceToGenericEvent(eventType, event)
		if err != nil {
			log.Printf("Failed to convert event to a generic event: %v\n", event)
		}
		if e == nil {
			log.Printf("Failed to convert event to a generic event (nil e): %v\n", event)
			return
		}

		// Get the rules that are bound to this event
		rules := engine.GetRulesForEvent(e)

		// Fetch the application profile (it should be faster than checking each rule if needed and then fetching it)
		appProfile, err := engine.applicationProfileCache.GetApplicationProfileAccess(e.ContainerName, e.ContainerID)
		if err != nil {
			log.Debugf("%v - error getting app profile: %v\n", e, err)
		}

		engine.ProcessEvent(eventType, event, appProfile, rules)
	})
}

func convertEventInterfaceToGenericEvent(eventType tracing.EventType, event interface{}) (*tracing.GeneralEvent, error) {
	// Switch on the event type
	switch eventType {
	case tracing.ExecveEventType:
		// Convert the event to an execve event
		execveEvent, ok := event.(*tracing.ExecveEvent)
		if !ok {
			return nil, fmt.Errorf("failed to convert event to an execve event: %v", event)
		} else {
			return &execveEvent.GeneralEvent, nil
		}
	case tracing.OpenEventType:
		// Convert the event to an open event
		openEvent, ok := event.(*tracing.OpenEvent)
		if !ok {
			return nil, fmt.Errorf("failed to convert event to an open event: %v", event)
		} else {
			return &openEvent.GeneralEvent, nil
		}
	case tracing.NetworkEventType:
		// Convert the event to a network event
		networkEvent, ok := event.(*tracing.NetworkEvent)
		if !ok {
			return nil, fmt.Errorf("failed to convert event to a network event: %v", event)
		} else {
			return &networkEvent.GeneralEvent, nil
		}
	case tracing.CapabilitiesEventType:
		// Convert the event to a capabilities event
		capabilitiesEvent, ok := event.(*tracing.CapabilitiesEvent)
		if !ok {
			return nil, fmt.Errorf("failed to convert event to a capabilities event: %v", event)
		} else {
			return &capabilitiesEvent.GeneralEvent, nil
		}
	case tracing.DnsEventType:
		// Convert the event to a dns event
		dnsEvent, ok := event.(*tracing.DnsEvent)
		if !ok {
			return nil, fmt.Errorf("failed to convert event to a dns event: %v", event)
		} else {
			return &dnsEvent.GeneralEvent, nil
		}
	case tracing.SyscallEventType:
		// Convert the event to a syscall event
		syscallEvent, ok := event.(*tracing.SyscallEvent)
		if !ok {
			return nil, fmt.Errorf("failed to convert event to a syscall event: %v", event)
		} else {
			return &syscallEvent.GeneralEvent, nil
		}
	case tracing.RandomXEventType:
		// Convert the event to a randomx event
		randomXEvent, ok := event.(*tracing.RandomXEvent)
		if !ok {
			return nil, fmt.Errorf("failed to convert event to a randomx event: %v", event)
		} else {
			return &randomXEvent.GeneralEvent, nil
		}
	default:
		return nil, fmt.Errorf("unknown event type: %v", eventType)
	}
}

// implement EventSink interface for the engine

func (engine *Engine) SendExecveEvent(event *tracing.ExecveEvent) {
	engine.promCollector.reportEbpfEvent(tracing.ExecveEventType)
	engine.submitEventForProcessing(event.ContainerID, tracing.ExecveEventType, event)
}

func (engine *Engine) SendOpenEvent(event *tracing.OpenEvent) {
	engine.promCollector.reportEbpfEvent(tracing.OpenEventType)
	engine.submitEventForProcessing(event.ContainerID, tracing.OpenEventType, event)
}

func (engine *Engine) SendNetworkEvent(event *tracing.NetworkEvent) {
	engine.promCollector.reportEbpfEvent(tracing.NetworkEventType)
	engine.submitEventForProcessing(event.ContainerID, tracing.NetworkEventType, event)
}

func (engine *Engine) SendCapabilitiesEvent(event *tracing.CapabilitiesEvent) {
	engine.promCollector.reportEbpfEvent(tracing.CapabilitiesEventType)
	engine.submitEventForProcessing(event.ContainerID, tracing.CapabilitiesEventType, event)
}

func (engine *Engine) SendDnsEvent(event *tracing.DnsEvent) {
	engine.promCollector.reportEbpfEvent(tracing.DnsEventType)
	engine.submitEventForProcessing(event.ContainerID, tracing.DnsEventType, event)
}

func (engine *Engine) SendRandomXEvent(event *tracing.RandomXEvent) {
	engine.promCollector.reportEbpfEvent(tracing.RandomXEventType)
	engine.submitEventForProcessing(event.ContainerID, tracing.RandomXEventType, event)
}

func (engine *Engine) ReportError(eventType tracing.EventType, err error) {
	engine.promCollector.reportEbpfFailedEvent()
}
