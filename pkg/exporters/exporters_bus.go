package exporters

import (
	"os"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/armosec/kubecop/pkg/engine/rule"
	"github.com/armosec/kubecop/pkg/scan"
)

type ExportersConfig struct {
	StdoutExporter           *bool               `yaml:"stdoutExporter"`
	AlertManagerExporterUrls string              `yaml:"alertManagerExporterUrls"`
	SyslogExporter           string              `yaml:"syslogExporterURL"`
	CsvRuleExporterPath      string              `yaml:"CsvRuleExporterPath"`
	CsvMalwareExporterPath   string              `yaml:"CsvMalwareExporterPath"`
	HTTPExporterConfig       *HTTPExporterConfig `yaml:"httpExporterConfig"`
}

// This file will contain the single point of contact for all exporters,
// it will be used by the engine to send alerts to all exporters.

const (
	// AlertManagerURLs separator delimiter.
	AlertManagerSepartorDelimiter = ","
)

type ExporterBus struct {
	// Exporters is a list of all exporters.
	exporters []Exporter
}

// InitExporters initializes all exporters.
func InitExporters(exportersConfig ExportersConfig) ExporterBus {
	exporters := []Exporter{}
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
	if exportersConfig.HTTPExporterConfig == nil {
		if httpURL := os.Getenv("HTTP_ENDPOINT_URL"); httpURL != "" {
			exportersConfig.HTTPExporterConfig = &HTTPExporterConfig{}
			exportersConfig.HTTPExporterConfig.URL = httpURL
		}
	}
	if exportersConfig.HTTPExporterConfig != nil {
		httpExp, err := InitHTTPExporter(*exportersConfig.HTTPExporterConfig)
		if err != nil {
			log.WithError(err).Error("failed to initialize HTTP exporter")
		}
		exporters = append(exporters, httpExp)
	}

	if len(exporters) == 0 {
		panic("no exporters were initialized")
	}
	log.Info("exporters initialized")

	return ExporterBus{exporters: exporters}
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

func (e *ExporterBus) SendRuleAlert(failedRule rule.RuleFailure) {
	for _, exporter := range e.exporters {
		exporter.SendRuleAlert(failedRule)
	}
}

func (e *ExporterBus) SendMalwareAlert(malwareDescription scan.MalwareDescription) {
	for _, exporter := range e.exporters {
		exporter.SendMalwareAlert(malwareDescription)
	}
}
