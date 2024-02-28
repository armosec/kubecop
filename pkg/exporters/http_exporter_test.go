package exporters

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/armosec/kubecop/pkg/engine/rule"
	"github.com/armosec/kubecop/pkg/scan"
	"github.com/kubescape/kapprofiler/pkg/tracing"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestSendRuleAlert(t *testing.T) {
	bodyChan := make(chan []byte, 1)
	// Create a mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("Failed to read request body: %v", err)
		}
		bodyChan <- body
	}))
	defer server.Close()

	// Create an HTTPExporter with the mock server URL
	exporter, err := InitHTTPExporter(HTTPExporterConfig{
		URL: server.URL,
	})
	assert.NoError(t, err)

	// Create a mock rule failure
	failedRule := &rule.R0001UnexpectedProcessLaunchedFailure{
		RulePriority: rule.RulePriorityCritical,
		RuleName:     "testrule",
		Err:          "Application profile is missing",
		FailureEvent: &tracing.ExecveEvent{GeneralEvent: tracing.GeneralEvent{
			ContainerName: "testcontainer", ContainerID: "testcontainerid", Namespace: "testnamespace", PodName: "testpodname"}},
	}

	// Call SendRuleAlert
	exporter.SendRuleAlert(failedRule)

	// Assert that the HTTP request was sent correctly
	alertsList := HTTPAlertsList{}
	select {
	case body := <-bodyChan:
		if err := json.Unmarshal(body, &alertsList); err != nil {
			t.Fatalf("Failed to unmarshal request body: %v", err)
		}

	case <-time.After(1 * time.Second):
		t.Fatalf("Timed out waiting for request body")
	}
	assert.Equal(t, "RuntimeAlerts", alertsList.Kind)
	assert.Equal(t, "kubescape.io/v1", alertsList.ApiVersion)
	assert.Equal(t, 1, len(alertsList.Spec.Alerts))
	alert := alertsList.Spec.Alerts[0]
	assert.Equal(t, rule.RulePriorityCritical, alert.Severity)
	assert.Equal(t, "testrule", alert.RuleName)
	assert.Equal(t, "testcontainerid", alert.ContainerID)
	assert.Equal(t, "testcontainer", alert.ContainerName)
	assert.Equal(t, "testnamespace", alert.PodNamespace)
	assert.Equal(t, "testpodname", alert.PodName)
}

func TestSendRuleAlertRateReached(t *testing.T) {
	bodyChan := make(chan []byte, 1)
	// Create a mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("Failed to read request body: %v", err)
		}
		bodyChan <- body
	}))
	defer server.Close()
	// Create an HTTPExporter with the mock server URL
	exporter, err := InitHTTPExporter(HTTPExporterConfig{
		URL:                server.URL,
		MaxAlertsPerMinute: 1,
	})
	assert.NoError(t, err)

	// Create a mock rule failure
	failedRule := &rule.R0001UnexpectedProcessLaunchedFailure{
		RulePriority: rule.RulePriorityCritical,
		RuleName:     "testrule",
		Err:          "Application profile is missing",
		FailureEvent: &tracing.ExecveEvent{GeneralEvent: tracing.GeneralEvent{
			ContainerName: "testcontainer", ContainerID: "testcontainerid", Namespace: "testnamespace", PodName: "testpodname"}},
	}

	// Call SendRuleAlert multiple times
	exporter.SendRuleAlert(failedRule)
	exporter.SendRuleAlert(failedRule)
	alertsList := HTTPAlertsList{}
	select {
	case body := <-bodyChan:
		if err := json.Unmarshal(body, &alertsList); err != nil {
			t.Fatalf("Failed to unmarshal request body: %v", err)
		}

	case <-time.After(1 * time.Second):
		t.Fatalf("Timed out waiting for request body")
	}
	// Assert that the second request was not sent
	alertsList = HTTPAlertsList{}
	select {
	case body := <-bodyChan:
		if err := json.Unmarshal(body, &alertsList); err != nil {
			t.Fatalf("Failed to unmarshal request body: %v", err)
		}

	case <-time.After(1 * time.Second):
		t.Fatalf("Timed out waiting for request body")
	}
	// Assert that the HTTP request contains the alert limit reached alert
	alert := alertsList.Spec.Alerts[0]
	assert.Equal(t, "AlertLimitReached", alert.RuleName)
	assert.Equal(t, "Alert limit reached", alert.Message)

}

func TestSendMalwareAlertHTTPExporter(t *testing.T) {
	bodyChan := make(chan []byte, 1)
	// Create a mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("Failed to read request body: %v", err)
		}
		bodyChan <- body
	}))
	defer server.Close()

	// Create an HTTPExporter with the mock server URL
	exporter, err := InitHTTPExporter(HTTPExporterConfig{
		URL: server.URL,
	})
	assert.NoError(t, err)

	// Create a mock malware description
	malwareDesc := scan.MalwareDescription{
		Name:           "testmalware",
		Description:    "testmalwaredescription",
		Path:           "testmalwarepath",
		Hash:           "testmalwarehash",
		Size:           "2MiB",
		Resource:       schema.EmptyObjectKind.GroupVersionKind().GroupVersion().WithResource("testmalwareresource"),
		Namespace:      "testmalwarenamespace",
		PodName:        "testmalwarepodname",
		ContainerName:  "testmalwarecontainername",
		ContainerID:    "testmalwarecontainerid",
		IsPartOfImage:  true,
		ContainerImage: "testmalwarecontainerimage",
	}

	// Call SendMalwareAlert
	exporter.SendMalwareAlert(malwareDesc)

	// Assert that the HTTP request was sent correctly
	alertsList := HTTPAlertsList{}
	select {
	case body := <-bodyChan:
		if err := json.Unmarshal(body, &alertsList); err != nil {
			t.Fatalf("Failed to unmarshal request body: %v", err)
		}

	case <-time.After(1 * time.Second):
		t.Fatalf("Timed out waiting for request body")
	}

	// Assert other expectations
	assert.Equal(t, "RuntimeAlerts", alertsList.Kind)
	assert.Equal(t, "kubescape.io/v1", alertsList.ApiVersion)
	assert.Equal(t, 1, len(alertsList.Spec.Alerts))
	alert := alertsList.Spec.Alerts[0]
	assert.Equal(t, "KubeCopMalwareDetected", alert.RuleName)
	assert.Equal(t, "testmalwarecontainerid", alert.ContainerID)
	assert.Equal(t, "testmalwarecontainername", alert.ContainerName)
	assert.Equal(t, "testmalwarenamespace", alert.PodNamespace)
	assert.Equal(t, "testmalwarepodname", alert.PodName)
}

func TestValidateHTTPExporterConfig(t *testing.T) {
	// Test case: URL is empty
	_, err := InitHTTPExporter(HTTPExporterConfig{})
	assert.Error(t, err)

	// Test case: URL is not empty
	exp, err := InitHTTPExporter(HTTPExporterConfig{
		URL: "http://localhost:9093",
	})
	assert.NoError(t, err)
	assert.Equal(t, "POST", exp.config.Method)
	assert.Equal(t, 1, exp.config.TimeoutSeconds)
	assert.Equal(t, 10000, exp.config.MaxAlertsPerMinute)
	assert.Equal(t, map[string]string{}, exp.config.Headers)

	// Test case: Method is PUT
	exp, err = InitHTTPExporter(HTTPExporterConfig{
		URL:                "http://localhost:9093",
		Method:             "PUT",
		TimeoutSeconds:     2,
		MaxAlertsPerMinute: 20000,
		Headers: map[string]string{
			"Authorization": "Bearer token",
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "PUT", exp.config.Method)
	assert.Equal(t, 2, exp.config.TimeoutSeconds)
	assert.Equal(t, 20000, exp.config.MaxAlertsPerMinute)
	assert.Equal(t, map[string]string{"Authorization": "Bearer token"}, exp.config.Headers)

	// Test case: Method is neither POST nor PUT
	_, err = InitHTTPExporter(HTTPExporterConfig{
		URL:    "http://localhost:9093",
		Method: "DELETE",
	})
	assert.Error(t, err)

}
