package exporters

import (
	"log"

	"github.com/armosec/kubecop/pkg/engine/rule"
)

type ExportersConfig struct {
	StdoutExporter          *bool  `yaml:"stdoutExporter"`
	AlertManagerExporterURL string `yaml:"alertManagerExporterURL"`
	SyslogExporter          string `yaml:"syslogExporterURL"`
	CsvExporterPath         string `yaml:"csvExporterPath"`
}

// This file will contain the single point of contact for all exporters,
// it will be used by the engine to send alerts to all exporters.

var (
	// Exporters is a list of all exporters.
	exporters []Exporter
)

// InitExporters initializes all exporters.
func InitExporters(exportersConfig ExportersConfig) {
	alertMan := InitAlertManagerExporter(exportersConfig.AlertManagerExporterURL)
	if alertMan != nil {
		exporters = append(exporters, alertMan)
	}
	stdoutExp := InitStdoutExporter(exportersConfig.StdoutExporter)
	if stdoutExp != nil {
		exporters = append(exporters, stdoutExp)
	}
	syslogExp := InitSyslogExporter(exportersConfig.SyslogExporter)
	if syslogExp != nil {
		exporters = append(exporters, syslogExp)
	}
	csvExp := InitCsvExporter(exportersConfig.CsvExporterPath)
	if csvExp != nil {
		exporters = append(exporters, csvExp)
	}

	if len(exporters) == 0 {
		panic("no exporters were initialized")
	}
	log.Print("exporters initialized")
}

func SendAlert(failedRule rule.RuleFailure) {
	for _, exporter := range exporters {
		exporter.SendAlert(failedRule)
	}
}
