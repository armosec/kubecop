package rule

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/prometheus/procfs"
	"golang.org/x/sys/unix"

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
	Tags:        []string{"exec", "whitelisted"},
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

	if !IsExecBinaryNotInBaseImage(execEvent) {
		return nil
	}

	return &R0006ExecBinaryNotInBaseImageFailure{
		RuleName:     rule.Name(),
		Err:          fmt.Sprintf("exec call \"%s\" binary is not from the base image", execEvent.PathName),
		FailureEvent: execEvent,
		RulePriority: R0006ExecBinaryNotInBaseImageRuleDescriptor.Priority,
	}
}

func IsExecBinaryNotInBaseImage(execEvent *tracing.ExecveEvent) bool {
	// Check if the path is in the upper layer.
	processes, err := findProcessByPathAndNamespace(execEvent)
	if err != nil {
		fmt.Printf("Error finding process by path and namespace: %s\n", err)
		return false
	}

	process := processes[0] // TODO: Verify that this is the correct process.

	upperLayerPath, err := getOverlayMountPoint(&process)
	if err != nil {
		return false
	}

	return !fileExists(filepath.Join(upperLayerPath, execEvent.PathName))
}

func findProcessByPathAndNamespace(execEvent *tracing.ExecveEvent) ([]procfs.Proc, error) {
	var matchingProcesses []procfs.Proc

	procs, err := procfs.AllProcs()
	if err != nil {
		return nil, err
	}

	mountNamespaceID, err := strconv.ParseUint(execEvent.Namespace, 10, 32)
	if err != nil {
		return nil, err
	}

	for _, proc := range procs {
		comm, err := proc.Comm()
		if err != nil {
			fmt.Printf("Error reading comm for PID %d: %s\n", proc.PID, err)
			continue
		}

		// Check if the executable comm matches the specified path comm
		if comm == filepath.Base(execEvent.PathName) {
			// Check if the mount namespace ID matches the specified namespaceID
			mountNamespaceId, err := getMountNamespaceID(proc.PID)
			if err != nil {
				fmt.Printf("Error reading mount namespace ID for PID %d: %s\n", proc.PID, err)
				continue
			}

			if mountNamespaceId == int(mountNamespaceID) {
				matchingProcesses = append(matchingProcesses, proc)
			}
		}
	}

	return matchingProcesses, nil
}

func getMountNamespaceID(pid int) (int, error) {
	var stat unix.Statfs_t
	err := unix.Statfs(fmt.Sprintf("/proc/%d/ns/mnt", pid), &stat)
	if err != nil {
		return 0, err
	}
	return int(stat.Type), nil
}

func getOverlayMountPoint(process *procfs.Proc) (string, error) {
	// Read the mount info for the process, and find the overlay mount point. (There should only be one?).
	if mounts, err := process.MountInfo(); err == nil {
		for _, mount := range mounts {
			if mount.FSType == "overlay" {
				return mount.Options["upperdir"], nil
			}
		}
	}

	return "", fmt.Errorf("failed to get mount point for pid %d", process.PID)
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
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
