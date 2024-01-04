package exporters

import (
	"log"

	"github.com/armosec/kubecop/pkg/engine/rule"
	"github.com/armosec/kubecop/pkg/scan"
)

type ExportersConfig struct {
	StdoutExporter          *bool  `yaml:"stdoutExporter"`
	AlertManagerExporterURL string `yaml:"alertManagerExporterURL"`
	SyslogExporter          string `yaml:"syslogExporterURL"`
	CsvRuleExporterPath     string `yaml:"csvRuleExporterPath"`
	CsvMalwareExporterPath  string `yaml:"csvMalwareExporterPath"`
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
	csvExp := InitCsvExporter(exportersConfig.CsvRuleExporterPath, exportersConfig.CsvMalwareExporterPath)
	if csvExp != nil {
		exporters = append(exporters, csvExp)
	}

	if len(exporters) == 0 {
		panic("no exporters were initialized")
	}
	log.Print("exporters initialized")
}

func SendRuleAlert(failedRule rule.RuleFailure) {
	for _, exporter := range exporters {
		exporter.SendRuleAlert(failedRule)
	}
}

func SendMalwareAlert(malwareDescription scan.MalwareDescription) {
	for _, exporter := range exporters {
		exporter.SendMalwareAlert(malwareDescription)
	}
}
