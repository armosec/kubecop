package exporters

import (
	"log"
	"log/syslog"
	"os"

	"github.com/armosec/kubecop/pkg/engine/rule"
)

// SyslogExporter is an exporter that sends alerts to syslog
type SyslogExporter struct {
	writer *syslog.Writer
}

// InitSyslogExporter initializes a new SyslogExporter
func InitSyslogExporter(syslogHost string) *SyslogExporter {
	if syslogHost == "" {
		syslogHost = os.Getenv("SYSLOG_HOST")
		if syslogHost == "" {
			return nil
		}
	}

	if os.Getenv("SYSLOG_PROTOCOL") == "" {
		os.Setenv("SYSLOG_PROTOCOL", "udp")
	}

	writer, err := syslog.Dial(os.Getenv("SYSLOG_PROTOCOL"), syslogHost, syslog.LOG_ERR, "kubecop")
	if err != nil {
		log.Printf("failed to initialize syslog exporter: %v", err)
		return nil
	}
	return &SyslogExporter{
		writer: writer,
	}
}

// SendAlert sends an alert to syslog
func (se *SyslogExporter) SendAlert(failedRule rule.RuleFailure) {
	err := se.writer.Err(failedRule.Error())
	if err != nil {
		log.Printf("failed to send alert to syslog: %v", err)
	}
}
