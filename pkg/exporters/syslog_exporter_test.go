package exporters

import (
	"os"
	"testing"
	"time"

	"github.com/armosec/kubecop/pkg/engine/rule"
	"github.com/kubescape/kapprofiler/pkg/tracing"
	"github.com/stretchr/testify/assert"
	"gopkg.in/mcuadros/go-syslog.v2"
)

func setupServer() *syslog.Server {
	channel := make(syslog.LogPartsChannel, 100)
	handler := syslog.NewChannelHandler(channel)

	server := syslog.NewServer()
	server.SetFormat(syslog.Automatic)
	server.SetHandler(handler)
	server.ListenUDP("0.0.0.0:514")
	server.Boot()

	go func(channel syslog.LogPartsChannel) {
		for logParts := range channel {
			// Assert logParts is not nil
			if assert.NotNil(nil, logParts) {
				// Assert logParts["content"] is not nil
				if assert.NotNil(nil, logParts["content"]) {
					// Assert logParts["message"].(string) is not empty
					assert.NotEmpty(nil, logParts["content"].(string))
				}
			} else {
				os.Exit(1)
			}
		}
	}(channel)

	go server.Wait()

	return server
}

func TestSyslogExporter(t *testing.T) {
	// Set up a mock syslog server
	server := setupServer()
	defer server.Kill()

	// Set up environment variables for the exporter
	syslogHost := "localhost:514"
	os.Setenv("SYSLOG_HOST", syslogHost)
	os.Setenv("SYSLOG_PROTOCOL", "udp")

	// Initialize the syslog exporter
	syslogExp := InitSyslogExporter("")
	if syslogExp == nil {
		t.Errorf("Expected syslogExp to not be nil")
	}

	// Send an alert
	syslogExp.SendAlert(&rule.R0001UnexpectedProcessLaunchedFailure{
		RuleName: "testrule",
		Err:      "Application profile is missing",
		FailureEvent: &tracing.ExecveEvent{GeneralEvent: tracing.GeneralEvent{
			ContainerName: "testcontainer", ContainerID: "testcontainerid", Namespace: "testnamespace", PodName: "testpodname"}},
	})

	// Allow some time for the message to reach the mock syslog server
	time.Sleep(200 * time.Millisecond)
}
