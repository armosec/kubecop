package engine

import (
	"fmt"
	"log"

	"github.com/kubescape/kapprofiler/pkg/tracing"
)

// This function enables prefiltering of events before they are processed by the engine.
func (engine *Engine) eventNeedsProcessing(event interface{}) bool {
	// TODO - implement
	// check if there are any rules that are bound to this event
	return true
}

// submitEventForProcessing submits an event for processing by the engine through the event processing pool.
// This decouples the event fire thread from the event processing thread.
func (engine *Engine) submitEventForProcessing(eventType tracing.EventType, event interface{}) {
	if !engine.eventNeedsProcessing(event) {
		return
	}

	// Add the event to a working group
	engine.eventProcessingPool.Submit(func() {
		// Convert the event to a generic event
		e, err := convertEventInterfaceToGenericEvent(eventType, event)
		if err != nil {
			log.Printf("Failed to convert event to a generic event: %v\n", event)
		}

		// Get the rules that are bound to this event
		rules := engine.GetRulesForEvent(e)

		// Fetch the application profile (it should be faster than checking each rule if needed and then fetching it)
		appProfile, err := engine.applicationProfileCache.GetApplicationProfileAccess(e.ContainerName, e.ContainerID)
		if err != nil {
			fmt.Printf("%v - error getting app profile: %v\n", e, err)
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
	default:
		return nil, fmt.Errorf("unknown event type: %v", eventType)
	}
}

// implement EventSink interface for the engine

func (engine *Engine) SendExecveEvent(event *tracing.ExecveEvent) {
	engine.submitEventForProcessing(tracing.ExecveEventType, event)
}

func (engine *Engine) SendOpenEvent(event *tracing.OpenEvent) {
	engine.submitEventForProcessing(tracing.OpenEventType, event)
}

func (engine *Engine) SendNetworkEvent(event *tracing.NetworkEvent) {
	engine.submitEventForProcessing(tracing.NetworkEventType, event)
}

func (engine *Engine) SendCapabilitiesEvent(event *tracing.CapabilitiesEvent) {
	engine.submitEventForProcessing(tracing.CapabilitiesEventType, event)
}

func (engine *Engine) SendDnsEvent(event *tracing.DnsEvent) {
	engine.submitEventForProcessing(tracing.DnsEventType, event)
}
