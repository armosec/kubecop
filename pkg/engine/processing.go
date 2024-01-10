package engine

import (
	log "github.com/sirupsen/logrus"

	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/armosec/kubecop/pkg/engine/rule"
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
			log.Debugf("%v - warning missing app profile", e)
			continue // TODO - check with the RuleBinding if alert should be fired or not
		}

		ruleFailure := rule.ProcessEvent(eventType, event, appProfile, engine)
		if ruleFailure != nil {
			engine.exporter.SendRuleAlert(ruleFailure)
			engine.promCollector.reportRuleAlereted(rule.Name())
		}
		engine.promCollector.reportRuleProcessed(rule.Name())
	}
}
