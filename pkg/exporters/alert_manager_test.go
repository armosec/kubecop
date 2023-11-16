package exporters

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/armosec/kubecop/pkg/engine/rule"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

func TestSendAlert(t *testing.T) {
	// Set up a mock Alertmanager server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	// os.Setenv("ALERTMANAGER_URL", "localhost:9093")

	// Create a new Alertmanager exporter
	exporter := InitAlertManagerExporter(server.URL)
	if exporter == nil {
		t.Fatalf("Failed to create new Alertmanager exporter")
	}
	// Call SendAlert

	exporter.SendAlert(&rule.R0001ExecWhitelistedFailure{
		RuleName: "testrule",
		Err:      "Application profile is missing",
		FailureEvent: &tracing.ExecveEvent{GeneralEvent: tracing.GeneralEvent{
			ContainerName: "testcontainer", ContainerID: "testcontainerid", Namespace: "testnamespace", PodName: "testpodname"}},
	})

	// Assert that the alert was sent successfully
	// expectedAlert := models.PostableAlert{
	// 	StartsAt:    strfmt.DateTime(time.Now()),
	// 	EndsAt:      strfmt.DateTime(time.Now().Add(time.Hour)),
	// 	Annotations: map[string]string{"summary": "Description of the alert"},
	// 	Alert: models.Alert{
	// 		GeneratorURL: "http://github.com/armosec/kubecop",
	// 		Labels:       map[string]string{"alertname": "MyAlertName", "severity": "critical"},
	// 	},
	// }
	// expectedParams := alert.NewPostAlertsParams().WithContext(context.Background()).WithAlerts(models.PostableAlerts{&expectedAlert})
	// assert.Equal(t, expectedParams, server.LastPostAlertsParams)
	// assert.Nil(t, restapi.LastPostAlertsBody)
	// assert.Equal(t, http.StatusOK, restapi.LastPostAlertsCode)
	// assert.Equal(t, "application/json", restapi.LastPostAlertsContentType)
	// assert.Equal(t, server.URL+"/api/v1/alerts", restapi.LastPostAlertsURL)
}
