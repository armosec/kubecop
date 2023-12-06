package exporters

import (
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/armosec/kubecop/pkg/engine/rule"
	"github.com/kubescape/kapprofiler/pkg/tracing"
	"github.com/stretchr/testify/assert"
	"gopkg.in/mcuadros/go-syslog.v2"
)

func setupServer(channel syslog.LogPartsChannel) *syslog.Server {
	handler := syslog.NewChannelHandler(channel)

	server := syslog.NewServer()
	server.SetFormat(syslog.RFC5424)
	server.SetHandler(handler)
	server.ListenUDP("0.0.0.0:514")
	server.Boot()

	go func(channel syslog.LogPartsChannel) {
		for logParts := range channel {
			fmt.Println(logParts)
		}
	}(channel)

	go server.Wait()

	return server
}

func TestSyslogExporter(t *testing.T) {
	// Set up a mock syslog server
	channel := make(syslog.LogPartsChannel, 10) // Buffered channel
	server := setupServer(channel)
	defer server.Kill()

	// Set up environment variables for the exporter
	syslogHost := "127.0.0.1:514"
	os.Setenv("SYSLOG_HOST", syslogHost)
	os.Setenv("SYSLOG_PROTOCOL", "udp")

	// Initialize the syslog exporter
	syslogExp := InitSyslogExporter("")

	// Send an alert
	syslogExp.SendAlert(&rule.R0001UnexpectedProcessLaunchedFailure{
		RuleName: "testrule",
		Err:      "Application profile is missing",
		FailureEvent: &tracing.ExecveEvent{GeneralEvent: tracing.GeneralEvent{
			ContainerName: "testcontainer", ContainerID: "testcontainerid", Namespace: "testnamespace", PodName: "testpodname"}},
	})

	// Allow some time for the message to reach the mock syslog server
	time.Sleep(1000 * time.Millisecond)

	// Assert the alert was received
	select {
	case logParts := <-channel:
		// Log received
		log.Print(logParts)
		assert.Equal(t, "testrule", logParts["rule_name"])
	case <-time.After(2 * time.Second):
		t.Errorf("Timeout waiting for syslog message")
	}
}
