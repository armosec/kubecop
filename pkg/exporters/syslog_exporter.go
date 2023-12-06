package exporters

import (
	"fmt"
	"log"
	"log/syslog"
	"os"
	"time"

	"github.com/crewjam/rfc5424"

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

	// Set default protocol to UDP
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

// SendAlert sends an alert to syslog (RFC 5424) - https://tools.ietf.org/html/rfc5424
func (se *SyslogExporter) SendAlert(failedRule rule.RuleFailure) {
	message := rfc5424.Message{
		Priority:  rfc5424.Error,
		Timestamp: time.Unix(failedRule.Event().Timestamp, 0),
		Hostname:  failedRule.Event().PodName,
		AppName:   failedRule.Event().ContainerName,
		Message: []byte(fmt.Sprintf(
			"Rule: %v Priority: %v Error: %v Fix Suggestion: %v Event: %v",
			failedRule.Name(),
			failedRule.Priority(),
			failedRule.Error(),
			failedRule.FixSuggestion(),
			failedRule.Event())),
	}

	_, err := message.WriteTo(se.writer)
	if err != nil {
		log.Printf("failed to send alert to syslog: %v", err)
	}
}
