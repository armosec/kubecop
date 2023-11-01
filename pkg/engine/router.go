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
		e, ok := event.(tracing.GeneralEvent)
		if !ok {
			log.Printf("Failed to convert event to a generic event: %v\n", event)
			return
		}

		// Get the rules that are bound to this event
		rules := engine.GetRulesForEvent(e)

		// Get the full workload kind and name
		workloadKind, workloadName, err := engine.GetWorkloadOwnerKindAndName(e)
		if err != nil {
			workloadKind = "Pod"
			workloadName = e.PodName
		}

		// Fetch the application profile (it should be faster than checking each rule if needed and then fetching it)
		appProfile, err := engine.applicationProfileCache.GetApplicationProfileAccess(e.Namespace, workloadKind, workloadName, e.ContainerID)
		if err != nil {
			fmt.Printf("%v - error getting app profile: %v\n", e, err)
		}

		engine.ProcessEvent(eventType, event, appProfile, rules)
	})
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
