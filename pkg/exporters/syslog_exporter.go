package exporters

import (
	"fmt"
	"log/syslog"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/crewjam/rfc5424"

	"github.com/armosec/kubecop/pkg/engine/rule"
	"github.com/armosec/kubecop/pkg/scan"
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

// SendRuleAlert sends an alert to syslog (RFC 5424) - https://tools.ietf.org/html/rfc5424
func (se *SyslogExporter) SendRuleAlert(failedRule rule.RuleFailure) {
	message := rfc5424.Message{
		Priority:  rfc5424.Error,
		Timestamp: time.Unix(failedRule.Event().Timestamp, 0),
		Hostname:  failedRule.Event().PodName,
		AppName:   failedRule.Event().ContainerName,
		ProcessID: fmt.Sprintf("%d", failedRule.Event().Pid),
		StructuredData: []rfc5424.StructuredData{
			{
				ID: fmt.Sprintf("kubecop@%d", failedRule.Event().Pid),
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
		log.Errorf("failed to send alert to syslog: %v", err)
	}
}

// SendMalwareAlert sends an alert to syslog (RFC 5424) - https://tools.ietf.org/html/rfc5424
func (se *SyslogExporter) SendMalwareAlert(malwareDescription scan.MalwareDescription) {
	message := rfc5424.Message{
		Priority:  rfc5424.Error,
		Timestamp: time.Now(),
		Hostname:  malwareDescription.PodName,
		AppName:   malwareDescription.ContainerName,
		ProcessID: fmt.Sprintf("%d", os.Getpid()), // TODO: is this correct?
		StructuredData: []rfc5424.StructuredData{
			{
				ID: fmt.Sprintf("kubecop@%d", os.Getpid()),
				Parameters: []rfc5424.SDParam{
					{
						Name:  "malware_name",
						Value: malwareDescription.Name,
					},
					{
						Name:  "description",
						Value: malwareDescription.Description,
					},
					{
						Name:  "path",
						Value: malwareDescription.Path,
					},
					{
						Name:  "hash",
						Value: malwareDescription.Hash,
					},
					{
						Name:  "size",
						Value: malwareDescription.Size,
					},
					{
						Name:  "namespace",
						Value: malwareDescription.Namespace,
					},
					{
						Name:  "pod_name",
						Value: malwareDescription.PodName,
					},
					{
						Name:  "container_name",
						Value: malwareDescription.ContainerName,
					},
					{
						Name:  "container_id",
						Value: malwareDescription.ContainerID,
					},
					{
						Name:  "is_part_of_image",
						Value: fmt.Sprintf("%t", malwareDescription.IsPartOfImage),
					},
					{
						Name:  "container_image",
						Value: malwareDescription.ContainerImage,
					},
				},
			},
		},
		Message: []byte(fmt.Sprintf("Malware '%s' detected in namespace '%s' pod '%s' description '%s' path '%s'", malwareDescription.Name, malwareDescription.Namespace, malwareDescription.PodName, malwareDescription.Description, malwareDescription.Path)),
	}

	_, err := message.WriteTo(se.writer)
	if err != nil {
		log.Errorf("failed to send alert to syslog: %v", err)
	}
}
