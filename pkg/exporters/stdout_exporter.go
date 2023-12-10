package exporters

import (
	"log/slog"
	"os"

	"github.com/armosec/kubecop/pkg/engine/rule"
)

type StdoutExporter struct {
	logger *slog.Logger
}

func InitStdoutExporter(useStdout *bool) *StdoutExporter {
	if useStdout == nil {
		useStdout = new(bool)
		*useStdout = os.Getenv("STDOUT_ENABLED") != "false"
	}
	if !*useStdout {
		return nil
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{}))
	return &StdoutExporter{
		logger: logger,
	}
}

func (exporter *StdoutExporter) SendAlert(failedRule rule.RuleFailure) {

	exporter.logger.Error(failedRule.Name(), slog.Int("severity", failedRule.Priority()),
		slog.String("message", failedRule.Error()), slog.Any("event", failedRule.Event()))
}
