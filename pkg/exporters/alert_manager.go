package exporters

// here we will have the functionality to export the alerts to the alert manager
// Path: pkg/exporters/alert_manager.go

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/armosec/kubecop/pkg/engine/rule"
	"github.com/go-openapi/strfmt"
	"github.com/prometheus/alertmanager/api/v2/client"
	"github.com/prometheus/alertmanager/api/v2/client/alert"
	"github.com/prometheus/alertmanager/api/v2/models"
)

type AlertManagerExporter struct {
	Host     string
	NodeName string
	client   *client.AlertmanagerAPI
}

func InitAlertManagerExporter(alertmanagerURL string) *AlertManagerExporter {
	// Create a new Alertmanager client
	cfg := client.DefaultTransportConfig().WithHost(alertmanagerURL)
	amClient := client.NewHTTPClientWithConfig(nil, cfg)
	hostName, err := os.Hostname()
	if err != nil {
		panic(fmt.Sprintf("failed to get hostname: %v", err))
	}

	return &AlertManagerExporter{
		client:   amClient,
		Host:     hostName,
		NodeName: os.Getenv("NODE_NAME"),
	}
}

func (ame *AlertManagerExporter) SendAlert(failedRule rule.RuleFailure) {
	sourceUrl := fmt.Sprintf("https://armosec.github.io/kubecop/alertviewer/?AlertMessage=%s&AlertRuleName=%s&AlertFix=%s&AlertNamespace=%s&AlertPod=%s&AlertContainer=%s&AlertProcess=%s",
		failedRule.Error(),
		failedRule.Name(),
		failedRule.FixSuggestion(),
		failedRule.Event().Namespace,
		failedRule.Event().PodName,
		failedRule.Event().ContainerName,
		fmt.Sprintf("%s (%d)", failedRule.Event().Comm, failedRule.Event().Pid),
	)
	summary := fmt.Sprintf("Rule '%s' in '%s' namespace '%s' failed", failedRule.Name(), failedRule.Event().PodName, failedRule.Event().Namespace)
	myAlert := models.PostableAlert{
		StartsAt: strfmt.DateTime(time.Now()),
		EndsAt:   strfmt.DateTime(time.Now().Add(time.Hour)),
		Annotations: map[string]string{
			"title":       summary,
			"summary":     summary,
			"message":     failedRule.Error(),
			"description": failedRule.Error(),
			"fix":         failedRule.FixSuggestion(),
		},
		Alert: models.Alert{
			GeneratorURL: strfmt.URI(sourceUrl),
			Labels: map[string]string{
				"alertname":      "KubeCopRuleViolated",
				"rule_name":      failedRule.Name(),
				"container_id":   failedRule.Event().ContainerID,
				"container_name": failedRule.Event().ContainerName,
				"namespace":      failedRule.Event().Namespace,
				"pod_name":       failedRule.Event().PodName,
				"severity":       PriorityToStatus(failedRule.Priority()),
				"host":           ame.Host,
				"node_name":      ame.NodeName,
				"pid":            fmt.Sprintf("%d", failedRule.Event().Pid),
				"ppid":           fmt.Sprintf("%d", failedRule.Event().Ppid),
				"comm":           failedRule.Event().Comm,
				"uid":            fmt.Sprintf("%d", failedRule.Event().Uid),
				"gid":            fmt.Sprintf("%d", failedRule.Event().Gid),
			},
		},
	}

	// Send the alert
	params := alert.NewPostAlertsParams().WithContext(context.Background()).WithAlerts(models.PostableAlerts{&myAlert})
	isOK, err := ame.client.Alert.PostAlerts(params)
	if err != nil {
		log.Println("Error sending alert:", err)
		return
	}
	if isOK == nil {
		log.Println("Alert was not sent successfully")
		return
	}
}
