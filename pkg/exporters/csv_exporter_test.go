package exporters

import (
	"encoding/csv"
	"os"
	"testing"

	"github.com/armosec/kubecop/pkg/engine/rule"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

func TestCsvExporter(t *testing.T) {
	csvExporter := InitCsvExporter("/tmp/kubecop.csv")
	if csvExporter == nil {
		t.Fatalf("Expected csvExporter to not be nil")
	}

	csvExporter.SendAlert(&rule.R0001UnexpectedProcessLaunchedFailure{
		RuleName: "testrule",
		Err:      "Application profile is missing",
		FailureEvent: &tracing.ExecveEvent{GeneralEvent: tracing.GeneralEvent{
			ContainerName: "testcontainer", ContainerID: "testcontainerid", Namespace: "testnamespace", PodName: "testpodname"}},
	})

	// Check if the csv file exists and contains the expected content (2 rows - header and the alert)
	if _, err := os.Stat("/tmp/kubecop.csv"); os.IsNotExist(err) {
		t.Fatalf("Expected csv file to exist")
	}

	csvFile, err := os.Open("/tmp/kubecop.csv")
	if err != nil {
		t.Fatalf("Expected csv file to open")
	}

	csvReader := csv.NewReader(csvFile)
	csvData, err := csvReader.ReadAll()
	if err != nil {
		t.Fatalf("Expected csv file to be readable")
	}

	if len(csvData) != 2 {
		t.Fatalf("Expected csv file to contain 2 rows")
	}

	if csvData[0][0] != "Rule Name" {
		t.Fatalf("Expected csv file to contain the rule name header")
	}

	csvFile.Close()

	err = os.Remove("/tmp/kubecop.csv")
	if err != nil {
		t.Fatalf("Expected csv file to be removed")
	}
}
