package engine

import (
	"log"
	"os"

	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/armosec/kubecop/pkg/engine/rule"
	"github.com/armosec/kubecop/pkg/exporters"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

func (engine *Engine) ProcessEvent(eventType tracing.EventType, event interface{}, appProfile approfilecache.SingleApplicationProfileAccess, boundRules []rule.Rule) {
	// Convert the event to a generic event
	e, err := convertEventInterfaceToGenericEvent(eventType, event)
	if err != nil {
		log.Printf("Failed to convert event to a generic event: %v\n", event)
	}

	// Loop over the boundRules
	for _, rule := range boundRules {
		// TODO if no app profile and one of the rules must have it then fire alert!
		if appProfile == nil && rule.Requirements().NeedApplicationProfile {
			if os.Getenv("DEBUG") == "true" {
				log.Printf("%v - warning missing app profile", e)
			}
			continue // TODO - check with the RuleBinding if alert should be fired or not
		}

		ruleFailure := rule.ProcessEvent(eventType, event, appProfile, engine)
		if ruleFailure != nil {
			exporters.SendAlert(ruleFailure)
			engine.promCollector.reportRuleAlereted(rule.Name())
		}
		engine.promCollector.reportRuleProcessed(rule.Name())
	}
}
