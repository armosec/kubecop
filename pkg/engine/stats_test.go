package engine

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kubescape/kapprofiler/pkg/tracing"
)

type MockStatPrinter struct {
	text string
}

func (m *MockStatPrinter) Print(v ...any) {
	m.text = fmt.Sprint(v...)
}

func (m *MockStatPrinter) GetText() string {
	return m.text
}

func TestEngineBasic(t *testing.T) {
	// Create a mock printer
	mockPrinter := MockStatPrinter{}
	engineStat := CreateStatComponent(&mockPrinter, 2*time.Second)
	defer engineStat.DestroyStatComponent()

	// Report some events
	engineStat.ReportEbpfEvent(tracing.ExecveEventType)
	engineStat.ReportEbpfEvent(tracing.ExecveEventType)
	engineStat.ReportEbpfEvent(tracing.ExecveEventType)

	// Report some rules
	engineStat.ReportRuleProcessed("rule1")
	engineStat.ReportRuleProcessed("rule1")

	// Report some alerts
	engineStat.ReportRuleAlereted("rule1")
	engineStat.ReportRuleAlereted("rule1")

	// Sleep for a while
	time.Sleep(3 * time.Second)

	// Check the output
	ebpfExpectation := "Execve: 3"
	ruleExpectation := "rule1: 2"
	alertExpectation := "rule1: 2"
	output := mockPrinter.GetText()
	// Chec ebpf expectation
	if strings.Contains(output, ebpfExpectation) == false {
		t.Errorf("Expected to find %s in %s", ebpfExpectation, output)
	}
	// Check rule expectation
	if strings.Contains(output, ruleExpectation) == false {
		t.Errorf("Expected to find %s in %s", ruleExpectation, output)
	}
	// Check alert expectation
	if strings.Contains(output, alertExpectation) == false {
		t.Errorf("Expected to find %s in %s", alertExpectation, output)
	}
}
