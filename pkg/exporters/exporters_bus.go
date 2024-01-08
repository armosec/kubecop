package exporters

import (
	"log"
	"os"
	"strings"

	"github.com/armosec/kubecop/pkg/engine/rule"
	"github.com/armosec/kubecop/pkg/scan"
)

type ExportersConfig struct {
	StdoutExporter           *bool  `yaml:"stdoutExporter"`
	AlertManagerExporterUrls string `yaml:"alertManagerExporterUrls"`
	SyslogExporter           string `yaml:"syslogExporterURL"`
	CsvRuleExporterPath      string `yaml:"CsvRuleExporterPath"`
	CsvMalwareExporterPath   string `yaml:"CsvMalwareExporterPath"`
}

// This file will contain the single point of contact for all exporters,
// it will be used by the engine to send alerts to all exporters.

const (
	// AlertManagerURLs separator delimiter.
	AlertManagerSepartorDelimiter = ","
)

var (
	// Exporters is a list of all exporters.
	exporters []Exporter
)

// InitExporters initializes all exporters.
func InitExporters(exportersConfig ExportersConfig) {
	alertManagerUrls := parseAlertManagerUrls(exportersConfig.AlertManagerExporterUrls)
	for _, url := range alertManagerUrls {
		alertMan := InitAlertManagerExporter(url)
		if alertMan != nil {
			exporters = append(exporters, alertMan)
		}
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

// ParseAlertManagerUrls parses the alert manager urls from the given string.
func parseAlertManagerUrls(urls string) []string {
	if urls == "" {
		urls = os.Getenv("ALERTMANAGER_URLS")
		if urls == "" {
			return nil
		}

		return strings.Split(urls, AlertManagerSepartorDelimiter)

	}
	return strings.Split(urls, AlertManagerSepartorDelimiter)
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
