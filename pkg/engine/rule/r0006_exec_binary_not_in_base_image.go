package rule

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/prometheus/procfs"

	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

const (
	R0006ID                               = "R0006"
	R0006ExecBinaryNotInBaseImageRuleName = "Exec Binary Not In Base Image"
	OVERLAY_FIELD_INDEX                   = 8
	MOUNT_POINT_FIELD_INDEX               = 9
	OVERLAY_LINE_FIELD_COUNT              = 10
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

type R0006ExecWhitelistedFailure struct {
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

	return &R0006ExecWhitelistedFailure{
		RuleName:     rule.Name(),
		Err:          fmt.Sprintf("exec call \"%s\" binary is not from the base image", execEvent.PathName),
		FailureEvent: execEvent,
		RulePriority: R0006ExecBinaryNotInBaseImageRuleDescriptor.Priority,
	}
}

func IsExecBinaryNotInBaseImage(execEvent *tracing.ExecveEvent) bool {
	// Check if the path is in the upper layer.
	// upperLayerPath, err := getOverlayMountPoint(execEvent.GeneralEvent.Pid)
	upperLayerPath, err := getOverlayMountPoint(1) // TODO: Replace with execEvent.GeneralEvent.Pid once the bug is fixed.
	if err != nil {
		return false
	}

	return !fileExists(filepath.Join(upperLayerPath, execEvent.PathName))
}

func getOverlayMountPoint(pid int) (string, error) {
	if mounts, err := procfs.GetProcMounts(pid); err == nil {
		for _, mount := range mounts {
			if mount.FSType == "overlay" {
				return mount.Options["upperdir"], nil
			}
		}
	}

	return "", fmt.Errorf("failed to get mount point for pid %d", pid)
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

func (rule *R0006ExecWhitelistedFailure) Name() string {
	return rule.RuleName
}

func (rule *R0006ExecWhitelistedFailure) Error() string {
	return rule.Err
}

func (rule *R0006ExecWhitelistedFailure) Event() tracing.GeneralEvent {
	return rule.FailureEvent.GeneralEvent
}

func (rule *R0006ExecWhitelistedFailure) Priority() int {
	return rule.RulePriority
}
