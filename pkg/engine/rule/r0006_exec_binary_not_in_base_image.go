package rule

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/prometheus/procfs"

	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

const (
	R0006ID                               = "R0006"
	R0006ExecBinaryNotInBaseImageRuleName = "Exec Binary Not In Base Image"
)

var R0006ExecBinaryNotInBaseImageRuleDescriptor = RuleDesciptor{
	ID:          R0006ID,
	Name:        R0006ExecBinaryNotInBaseImageRuleName,
	Description: "Detecting exec calls of binaries that are not included in the base image",
	Tags:        []string{"exec", "malicious", "binary", "base image"},
	Priority:    7,
	Requirements: RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.ExecveEventType},
		NeedApplicationProfile: false,
	},
	RuleCreationFunc: func() Rule {
		return CreateRuleR0006ExecBinaryNotInBaseImage()
	},
}

type R0006ExecBinaryNotInBaseImage struct {
}

type R0006ExecBinaryNotInBaseImageFailure struct {
	RuleName     string
	Err          string
	RulePriority int
	FailureEvent *tracing.ExecveEvent
}

func (rule *R0006ExecBinaryNotInBaseImage) Name() string {
	return R0006ExecBinaryNotInBaseImageRuleName
}

func CreateRuleR0006ExecBinaryNotInBaseImage() *R0006ExecBinaryNotInBaseImage {
	return &R0006ExecBinaryNotInBaseImage{}
}

func (rule *R0006ExecBinaryNotInBaseImage) DeleteRule() {
}

func (rule *R0006ExecBinaryNotInBaseImage) ProcessEvent(eventType tracing.EventType, event interface{}, appProfileAccess approfilecache.SingleApplicationProfileAccess) RuleFailure {
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

	return &R0006ExecBinaryNotInBaseImageFailure{
		RuleName:     rule.Name(),
		Err:          fmt.Sprintf("exec call \"%s\" \"%s\" binary is not from the base image", execEvent.PathName, strings.Join(execEvent.Args, " ")),
		FailureEvent: execEvent,
		RulePriority: R0006ExecBinaryNotInBaseImageRuleDescriptor.Priority,
	}
}

func IsExecBinaryInUpperLayer(execEvent *tracing.ExecveEvent) bool {
	// Find a process with the same mount namespace ID as the exec event.
	process, err := findProcessByMountNamespace(execEvent)
	if err != nil {
		fmt.Printf("Error finding process by mount namespace: %s\n", err)
		return false
	}

	// Get the overlay mount point for the process.
	upperLayerPath, err := getOverlayMountPoint(process)
	if err != nil {
		return false
	}

	log.Printf("Checking if %s exists in %s\n", execEvent.PathName, upperLayerPath)

	return fileExists(filepath.Join(upperLayerPath, execEvent.PathName))
}

func findProcessByMountNamespace(execEvent *tracing.ExecveEvent) (*procfs.Proc, error) {
	procs, err := procfs.AllProcs()
	if err != nil {
		return nil, err
	}

	for _, proc := range procs {
		comm, err := proc.Comm()
		if err != nil {
			fmt.Printf("Error reading comm for PID %d: %s\n", proc.PID, err)
			continue
		}

		log.Printf("Checking process %d (%s)\n", proc.PID, comm)

		// Check if the mount namespace ID matches the specified namespaceID
		mountNamespaceId, err := getMountNamespaceID(proc.PID)
		if err != nil {
			fmt.Printf("Error reading mount namespace ID for PID %d: %s\n", proc.PID, err)
			continue
		}

		log.Printf("Comparing %d to %d\n", mountNamespaceId, execEvent.MountNsID)

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
		log.Printf("File %s does not exist %s \n", filePath, err)
		return false
	}

	return !info.IsDir()
}

func (rule *R0006ExecBinaryNotInBaseImage) Requirements() RuleRequirements {
	return RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.ExecveEventType},
		NeedApplicationProfile: false,
	}
}

func (rule *R0006ExecBinaryNotInBaseImageFailure) Name() string {
	return rule.RuleName
}

func (rule *R0006ExecBinaryNotInBaseImageFailure) Error() string {
	return rule.Err
}

func (rule *R0006ExecBinaryNotInBaseImageFailure) Event() tracing.GeneralEvent {
	return rule.FailureEvent.GeneralEvent
}

func (rule *R0006ExecBinaryNotInBaseImageFailure) Priority() int {
	return rule.RulePriority
}
