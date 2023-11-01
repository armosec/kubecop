package engine

import (
	"fmt"
	"log"

	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/armosec/kubecop/pkg/engine/rule"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

func (engine *Engine) ProcessEvent(eventType tracing.EventType, event interface{}, appProfile approfilecache.SingleApplicationProfileAccess, boundRules []rule.Rule) {
	// Convert the event to a generic event
	e, ok := event.(tracing.GeneralEvent)
	if !ok {
		log.Printf("Failed to convert event to a generic event: %v\n", event)
		return
	}

	// Loop over the boundRules
	for _, rule := range boundRules {
		// TODO if no app profile and one of the rules must have it then fire alert!
		if appProfile == nil && rule.Requirements().NeedApplicationProfile {
			fmt.Printf("%v - warning missing app profile", e)
		}

		ruleFailure := rule.ProcessEvent(eventType, event, appProfile)
		if ruleFailure != nil {
			// TODO need an alertfiring interface and fire an alert
			fmt.Printf("%v - Alert %s\n", e, ruleFailure.Error())
		}
	}
}
