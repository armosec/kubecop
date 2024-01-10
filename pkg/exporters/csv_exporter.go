package exporters

import (
	"encoding/csv"
	"fmt"
	"os"

	"github.com/armosec/kubecop/pkg/engine/rule"
	"github.com/armosec/kubecop/pkg/scan"
	"github.com/sirupsen/logrus"
)

// CsvExporter is an exporter that sends alerts to csv
type CsvExporter struct {
	CsvRulePath    string
	CsvMalwarePath string
}

// InitCsvExporter initializes a new CsvExporter
func InitCsvExporter(csvRulePath, csvMalwarePath string) *CsvExporter {
	if csvRulePath == "" {
		csvRulePath = os.Getenv("EXPORTER_CSV_RULE_PATH")
		if csvRulePath == "" {
			logrus.Debugf("csv rule path not provided, rule alerts will not be exported to csv")
			return nil
		}
	}

	if csvMalwarePath == "" {
		csvMalwarePath = os.Getenv("EXPORTER_CSV_MALWARE_PATH")
		if csvMalwarePath == "" {
			logrus.Debugf("csv malware path not provided, malware alerts will not be exported to csv")
		}
	}

	if _, err := os.Stat(csvRulePath); os.IsNotExist(err) {
		writeRuleHeaders(csvRulePath)
	}

	if _, err := os.Stat(csvMalwarePath); os.IsNotExist(err) && csvMalwarePath != "" {
		writeMalwareHeaders(csvMalwarePath)
	}

	return &CsvExporter{
		CsvRulePath:    csvRulePath,
		CsvMalwarePath: csvMalwarePath,
	}
}

// SendRuleAlert sends an alert to csv
func (ce *CsvExporter) SendRuleAlert(failedRule rule.RuleFailure) {
	csvFile, err := os.OpenFile(ce.CsvRulePath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		logrus.Errorf("failed to initialize csv exporter: %v", err)
		return
	}
	defer csvFile.Close()

	csvWriter := csv.NewWriter(csvFile)
	defer csvWriter.Flush()
	csvWriter.Write([]string{
		failedRule.Name(),
		failedRule.Error(),
		failedRule.FixSuggestion(),
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

func writeRuleHeaders(csvPath string) {
	csvFile, err := os.OpenFile(csvPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logrus.Errorf("failed to initialize csv exporter: %v", err)
		return
	}
	defer csvFile.Close()

	csvWriter := csv.NewWriter(csvFile)
	defer csvWriter.Flush()
	csvWriter.Write([]string{
		"Rule Name",
		"Alert Message",
		"Fix Suggestion",
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

func (ce *CsvExporter) SendMalwareAlert(malwareDescription scan.MalwareDescription) {
	csvFile, err := os.OpenFile(ce.CsvMalwarePath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		logrus.Errorf("failed to initialize csv exporter: %v", err)
		return
	}
	defer csvFile.Close()

	csvWriter := csv.NewWriter(csvFile)
	defer csvWriter.Flush()
	csvWriter.Write([]string{
		malwareDescription.Name,
		malwareDescription.Description,
		malwareDescription.Path,
		malwareDescription.Hash,
		malwareDescription.Size,
		malwareDescription.Resource.String(),
		malwareDescription.Namespace,
		malwareDescription.PodName,
		malwareDescription.ContainerName,
		malwareDescription.ContainerID,
		fmt.Sprintf("%t", malwareDescription.IsPartOfImage),
		malwareDescription.ContainerImage,
	})
}

// Write Malware Headers
func writeMalwareHeaders(csvPath string) {
	csvFile, err := os.OpenFile(csvPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logrus.Errorf("failed to initialize csv exporter: %v", err)
		return
	}
	defer csvFile.Close()

	csvWriter := csv.NewWriter(csvFile)
	defer csvWriter.Flush()
	csvWriter.Write([]string{
		"Malware Name",
		"Description",
		"Path",
		"Hash",
		"Size",
		"Resource",
		"Namespace",
		"Pod Name",
		"Container Name",
		"Container ID",
		"Is Part of Image",
		"Container Image",
	})
}
