package exporters

import "github.com/armosec/kubecop/pkg/engine/rule"

// generic exporter interface
type Exporter interface {
	// SendAlert sends an alert to the exporter
	SendAlert(failedRule rule.RuleFailure)
}
