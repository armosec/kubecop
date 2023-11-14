package exporters

// here we will have the functionality to export the alerts to the alert manager
// Path: pkg/exporters/alert_manager.go

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/prometheus/alertmanager/api/v2/client"
	"github.com/prometheus/alertmanager/api/v2/client/alert"
	"github.com/prometheus/alertmanager/api/v2/models"
)

type AlertManagerExporter struct {
	client *client.AlertmanagerAPI
}

func InitAlertManagerExporter() (*AlertManagerExporter, error) {
	alertmanagerURL := os.Getenv("ALERTMANAGER_URL")
	if alertmanagerURL == "" {
		return nil, fmt.Errorf("ALERTMANAGER_URL environment variable is not set")
	}
	// Create a new Alertmanager client
	cfg := client.DefaultTransportConfig().WithHost(alertmanagerURL)
	amClient := client.NewHTTPClientWithConfig(nil, cfg)
	return &AlertManagerExporter{
		client: amClient,
	}, nil
}

func (ame *AlertManagerExporter) SendAlert() {
	// Define your alert
	myAlert := models.PostableAlert{
		StartsAt:    strfmt.DateTime(time.Now()),
		EndsAt:      strfmt.DateTime(time.Now().Add(time.Hour)),
		Annotations: map[string]string{"summary": "Description of the alert"},
		Alert: models.Alert{
			GeneratorURL: "http://github.com/armosec/kubecop",
			Labels:       map[string]string{"alertname": "MyAlertName", "severity": "critical"},
		},
	}

	// Send the alert
	params := alert.NewPostAlertsParams().WithContext(context.Background()).WithAlerts(models.PostableAlerts{&myAlert})
	isOK, err := ame.client.Alert.PostAlerts(params)
	if err != nil {
		fmt.Println("Error sending alert:", err)
		return
	}
	if isOK == nil {
		fmt.Println("Alert was not sent successfully")
		return
	}

	fmt.Printf("Alert sent successfully: %v\n", isOK)
}
