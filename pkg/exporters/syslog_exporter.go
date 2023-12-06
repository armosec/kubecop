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
		ProcessID: fmt.Sprintf("%d", failedRule.Event().Pid),
		StructuredData: []rfc5424.StructuredData{
			{
				ID: "kubecop - General Event",
				Parameters: []rfc5424.SDParam{
					{
						Name:  "rule",
						Value: failedRule.Name(),
					},
					{
						Name:  "priority",
						Value: fmt.Sprintf("%d", failedRule.Priority()),
					},
					{
						Name:  "error",
						Value: failedRule.Error(),
					},
					{
						Name:  "fix_suggestion",
						Value: failedRule.FixSuggestion(),
					},
					{
						Name:  "ppid",
						Value: fmt.Sprintf("%d", failedRule.Event().Ppid),
					},
					{
						Name:  "comm",
						Value: failedRule.Event().Comm,
					},
					{
						Name:  "uid",
						Value: fmt.Sprintf("%d", failedRule.Event().Uid),
					},
					{
						Name:  "gid",
						Value: fmt.Sprintf("%d", failedRule.Event().Gid),
					},
					{
						Name:  "namespace",
						Value: failedRule.Event().Namespace,
					},
					{
						Name:  "pod_name",
						Value: failedRule.Event().PodName,
					},
					{
						Name:  "container_name",
						Value: failedRule.Event().ContainerName,
					},
					{
						Name:  "container_id",
						Value: failedRule.Event().ContainerID,
					},
					{
						Name:  "cwd",
						Value: failedRule.Event().Cwd,
					},
				},
			},
		},
		Message: []byte(failedRule.Error()),
	}

	_, err := message.WriteTo(se.writer)
	if err != nil {
		log.Printf("failed to send alert to syslog: %v", err)
	}
}
