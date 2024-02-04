package rule

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/prometheus/procfs"
	log "github.com/sirupsen/logrus"

	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

const (
	R1001ID                               = "R1001"
	R1001ExecBinaryNotInBaseImageRuleName = "Exec Binary Not In Base Image"
)

var R1001ExecBinaryNotInBaseImageRuleDescriptor = RuleDesciptor{
	ID:          R1001ID,
	Name:        R1001ExecBinaryNotInBaseImageRuleName,
	Description: "Detecting exec calls of binaries that are not included in the base image",
	Tags:        []string{"exec", "malicious", "binary", "base image"},
	Priority:    RulePriorityCritical,
	Requirements: RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.ExecveEventType},
		NeedApplicationProfile: false,
	},
	RuleCreationFunc: func() Rule {
		return CreateRuleR1001ExecBinaryNotInBaseImage()
	},
}

type R1001ExecBinaryNotInBaseImage struct {
	BaseRule
}

type R1001ExecBinaryNotInBaseImageFailure struct {
	RuleName         string
	Err              string
	FixSuggestionMsg string
	RulePriority     int
	FailureEvent     *tracing.ExecveEvent
}

func (rule *R1001ExecBinaryNotInBaseImage) Name() string {
	return R1001ExecBinaryNotInBaseImageRuleName
}

func CreateRuleR1001ExecBinaryNotInBaseImage() *R1001ExecBinaryNotInBaseImage {
	return &R1001ExecBinaryNotInBaseImage{}
}

func (rule *R1001ExecBinaryNotInBaseImage) DeleteRule() {
}

func (rule *R1001ExecBinaryNotInBaseImage) ProcessEvent(eventType tracing.EventType, event interface{}, appProfileAccess approfilecache.SingleApplicationProfileAccess, engineAccess EngineAccess) RuleFailure {
	if eventType != tracing.ExecveEventType {
		return nil
	}

	execEvent, ok := event.(*tracing.ExecveEvent)
	if !ok {
		return nil
	}

	if !IsExecBinaryInUpperLayer(execEvent) {
		return nil
	}

	return &R1001ExecBinaryNotInBaseImageFailure{
		RuleName:         rule.Name(),
		Err:              fmt.Sprintf("Process image \"%s\" binary is not from the container image \"%s\"", execEvent.PathName, "<image name TBA> via PodSpec"),
		FixSuggestionMsg: "If this is an expected behavior it is strongly suggested to include all executables in the container image. If this is not possible you can remove the rule binding to this workload.",
		FailureEvent:     execEvent,
		RulePriority:     R1001ExecBinaryNotInBaseImageRuleDescriptor.Priority,
	}
}

func IsExecBinaryInUpperLayer(execEvent *tracing.ExecveEvent) bool {
	// Find a process with the same mount namespace ID as the exec event.
	process, err := findProcessByMountNamespace(execEvent)
	if err != nil {
		//log.Printf("Error finding process by mount namespace: %s\n", err)
		return false
	}

	// Get the overlay mount point for the process.
	upperLayerPath, err := getOverlayMountPoint(process)
	if err != nil {
		return false
	}

	return fileExists(filepath.Join(upperLayerPath, execEvent.PathName))
}

func findProcessByMountNamespace(execEvent *tracing.ExecveEvent) (*procfs.Proc, error) {
	procs, err := procfs.AllProcs()
	if err != nil {
		return nil, err
	}

	for _, proc := range procs {
		// Check if the mount namespace ID matches the specified namespaceID
		mountNamespaceId, err := getMountNamespaceID(proc.PID)
		if err != nil {
			log.Debugf("Error reading mount namespace ID for PID %d: %s\n", proc.PID, err)
			continue
		}

		if mountNamespaceId == execEvent.MountNsID {
			return &proc, nil
		}

	}

	return nil, fmt.Errorf("no matching process found for mount namespace %d", execEvent.MountNsID)
}

func getMountNamespaceID(pid int) (uint64, error) {
	nsPath := fmt.Sprintf("/proc/%d/ns/mnt", pid)

	stat := syscall.Stat_t{}
	err := syscall.Stat(nsPath, &stat)
	if err != nil {
		return 0, err
	}

	return stat.Ino, nil
}

func getOverlayMountPoint(process *procfs.Proc) (string, error) {
	// Read the mount info for the process, and find the overlay mount point. (There should only be one?).
	if mounts, err := process.MountInfo(); err == nil {
		for _, mount := range mounts {
			if mount.FSType == "overlay" {
				return mount.SuperOptions["upperdir"], nil
			}
		}
	}

	return "", fmt.Errorf("failed to get mount point for pid %d", process.PID)
}

func fileExists(filePath string) bool {
	info, err := os.Stat(filepath.Join("/host", filePath))
	if os.IsNotExist(err) {
		log.Debugf("File %s does not exist %s \n", filePath, err)
		return false
	}

	return !info.IsDir()
}

func (rule *R1001ExecBinaryNotInBaseImage) Requirements() RuleRequirements {
	return RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.ExecveEventType},
		NeedApplicationProfile: false,
	}
}

func (rule *R1001ExecBinaryNotInBaseImageFailure) Name() string {
	return rule.RuleName
}

func (rule *R1001ExecBinaryNotInBaseImageFailure) Error() string {
	return rule.Err
}

func (rule *R1001ExecBinaryNotInBaseImageFailure) Event() tracing.GeneralEvent {
	return rule.FailureEvent.GeneralEvent
}

func (rule *R1001ExecBinaryNotInBaseImageFailure) Priority() int {
	return rule.RulePriority
}

func (rule *R1001ExecBinaryNotInBaseImageFailure) FixSuggestion() string {
	return rule.FixSuggestionMsg
}
