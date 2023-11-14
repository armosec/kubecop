package exporters

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestSendAlert(t *testing.T) {
	// Set up a mock Alertmanager server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Set the ALERTMANAGER_URL environment variable to the mock server URL
	os.Setenv("ALERTMANAGER_URL", server.URL)
	os.Setenv("ALERTMANAGER_URL", "localhost:9093")

	// Create a new Alertmanager exporter
	exporter, err := InitAlertManagerExporter()
	if err != nil {
		t.Fatalf("Failed to create new Alertmanager exporter: %v", err)
	}
	// Call SendAlert
	exporter.SendAlert()

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
