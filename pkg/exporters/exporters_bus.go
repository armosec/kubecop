package exporters

import (
	"fmt"

	"github.com/armosec/kubecop/pkg/engine/rule"
)

type ExportersConfig struct {
	StdoutExporter          *bool  `yaml:"stdoutExporter"`
	AlertManagerExporterURL string `yaml:"alertManagerExporterURL"`
}

// this file will contain the single point of contact for all exporters
// it will be used by the engine to send alerts to all exporters

var (
	// Exporters is a list of all exporters
	exporters []Exporter
)

// InitExporters initializes all exporters
func InitExporters(exportersConfig ExportersConfig) {
	alertMan := InitAlertManagerExporter(exportersConfig.AlertManagerExporterURL)
	if alertMan != nil {
		exporters = append(exporters, alertMan)
	}
	stdoutExp := InitStdoutExporter(exportersConfig.StdoutExporter)
	if stdoutExp != nil {
		exporters = append(exporters, stdoutExp)
	}
	if len(exporters) == 0 {
		panic("no exporters were initialized")
	}
	fmt.Println("exporters initialized")
}

func SendAlert(failedRule rule.RuleFailure) {
	for _, exporter := range exporters {
		exporter.SendAlert(failedRule)
	}
}
