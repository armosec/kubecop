package exporters

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"

	"github.com/armosec/kubecop/pkg/engine/rule"
)

// CsvExporter is an exporter that sends alerts to csv
type CsvExporter struct {
	CsvPath string
}

// InitCsvExporter initializes a new CsvExporter
func InitCsvExporter(csvPath string) *CsvExporter {
	if csvPath == "" {
		csvPath = os.Getenv("EXPORTER_CSV_PATH")
		if csvPath == "" {
			return nil
		}
	}

	if _, err := os.Stat(csvPath); os.IsNotExist(err) {
		writeHeaders(csvPath)
	}

	return &CsvExporter{
		CsvPath: csvPath,
	}
}

// SendAlert sends an alert to csv
func (ce *CsvExporter) SendAlert(failedRule rule.RuleFailure) {
	csvFile, err := os.OpenFile(ce.CsvPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("failed to initialize csv exporter: %v", err)
		return
	}
	defer csvFile.Close()

	csvWriter := csv.NewWriter(csvFile)
	defer csvWriter.Flush()
	csvWriter.Write([]string{
		failedRule.Name(),
		failedRule.Event().PodName,
		failedRule.Event().ContainerName,
		failedRule.Event().Namespace,
		failedRule.Event().ContainerID,
		fmt.Sprintf("%d", failedRule.Event().Pid),
		failedRule.Event().Comm,
		failedRule.Event().Cwd,
		fmt.Sprintf("%d", failedRule.Event().Uid),
		fmt.Sprintf("%d", failedRule.Event().Gid),
		fmt.Sprintf("%d", failedRule.Event().Ppid),
		fmt.Sprintf("%d", failedRule.Event().MountNsID),
		fmt.Sprintf("%d", failedRule.Event().Timestamp),
	})
}

func writeHeaders(csvPath string) {
	csvFile, err := os.OpenFile(csvPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("failed to initialize csv exporter: %v", err)
		return
	}
	defer csvFile.Close()

	csvWriter := csv.NewWriter(csvFile)
	defer csvWriter.Flush()
	csvWriter.Write([]string{
		"Rule Name",
		"Pod Name",
		"Container Name",
		"Namespace",
		"Container ID",
		"PID",
		"Comm",
		"Cwd",
		"UID",
		"GID",
		"PPID",
		"Mount Namespace ID",
		"Timestamp",
	})
}
