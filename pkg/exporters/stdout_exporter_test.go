package exporters

import (
	"os"
	"testing"

	"github.com/armosec/kubecop/pkg/engine/rule"
	"github.com/kubescape/kapprofiler/pkg/tracing"
	"github.com/stretchr/testify/assert"
)

func TestInitStdoutExporter(t *testing.T) {
	// Test when useStdout is nil
	useStdout := new(bool)
	exporter := InitStdoutExporter(nil)
	assert.NotNil(t, exporter)

	// Test when useStdout is true
	useStdout = new(bool)
	*useStdout = true
	exporter = InitStdoutExporter(useStdout)
	assert.NotNil(t, exporter)
	assert.NotNil(t, exporter.logger)

	// Test when useStdout is false
	useStdout = new(bool)
	*useStdout = false
	exporter = InitStdoutExporter(useStdout)
	assert.Nil(t, exporter)

	// Test when STDOUT_ENABLED environment variable is set to "false"
	os.Setenv("STDOUT_ENABLED", "false")
	exporter = InitStdoutExporter(nil)
	assert.Nil(t, exporter)

	// Test when STDOUT_ENABLED environment variable is set to "true"
	os.Setenv("STDOUT_ENABLED", "true")
	exporter = InitStdoutExporter(nil)
	assert.NotNil(t, exporter)
	assert.NotNil(t, exporter.logger)

	// Test when STDOUT_ENABLED environment variable is not set
	os.Unsetenv("STDOUT_ENABLED")
	exporter = InitStdoutExporter(nil)
	assert.NotNil(t, exporter)
	assert.NotNil(t, exporter.logger)
}

func TestStdoutExporter_SendAlert(t *testing.T) {
	exporter := InitStdoutExporter(nil)
	assert.NotNil(t, exporter)

	exporter.SendRuleAlert(&rule.R0001UnexpectedProcessLaunchedFailure{
		RuleName: "testrule",
		Err:      "Application profile is missing",
		FailureEvent: &tracing.ExecveEvent{GeneralEvent: tracing.GeneralEvent{
			ContainerName: "testcontainer", ContainerID: "testcontainerid", Namespace: "testnamespace", PodName: "testpodname"}},
	})
}
