package rule

import (
	"fmt"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

const (
	R1004ID                    = "R1004"
	R1004ExecFromMountRuleName = "Exec from mount"
)

var R1004ExecFromMountRuleDescriptor = RuleDesciptor{
	ID:          R1004ID,
	Name:        R1004ExecFromMountRuleName,
	Description: "Detecting exec calls from mounted paths.",
	Tags:        []string{"exec", "mount"},
	Priority:    RulePriorityMed,
	Requirements: RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.ExecveEventType},
		NeedApplicationProfile: false,
	},
	RuleCreationFunc: func() Rule {
		return CreateRuleR1004ExecFromMount()
	},
}

type R1004ExecFromMount struct {
	BaseRule
	// Map of container ID to mount paths
	mutex                   sync.RWMutex
	containerIdToMountPaths map[string][]string
}

type R1004ExecFromMountFailure struct {
	RuleName         string
	RulePriority     int
	Err              string
	FixSuggestionMsg string
	FailureEvent     *tracing.ExecveEvent
}

func (rule *R1004ExecFromMount) Name() string {
	return R1004ExecFromMountRuleName
}

func CreateRuleR1004ExecFromMount() *R1004ExecFromMount {
	return &R1004ExecFromMount{
		containerIdToMountPaths: map[string][]string{},
	}
}

func (rule *R1004ExecFromMount) DeleteRule() {
}

func (rule *R1004ExecFromMount) ProcessEvent(eventType tracing.EventType, event interface{}, appProfileAccess approfilecache.SingleApplicationProfileAccess, engineAccess EngineAccess) RuleFailure {
	if eventType != tracing.ExecveEventType {
		return nil
	}

	execEvent, ok := event.(*tracing.ExecveEvent)
	if !ok {
		return nil
	}

	rule.mutex.RLock()
	mounts, ok := rule.containerIdToMountPaths[execEvent.ContainerID]
	rule.mutex.RUnlock()
	if !ok {
		err := rule.setMountPaths(execEvent.PodName, execEvent.Namespace, execEvent.ContainerID, execEvent.ContainerName, engineAccess)
		if err != nil {
			log.Printf("Failed to set mount paths: %v", err)
			return nil
		}
		rule.mutex.RLock()
		mounts = rule.containerIdToMountPaths[execEvent.ContainerID]
		rule.mutex.RUnlock()
	}

	for _, mount := range mounts {
		contained := rule.isPathContained(execEvent.PathName, mount)
		if contained {
			log.Debugf("Path %s is mounted in pod %s/%s", execEvent.PathName, execEvent.Namespace, execEvent.PodName)
			return &R1004ExecFromMountFailure{
				RuleName:         rule.Name(),
				Err:              "Exec from mount",
				FailureEvent:     execEvent,
				FixSuggestionMsg: "If this is a legitimate action, please consider removing this workload from the binding of this rule",
				RulePriority:     R1004ExecFromMountRuleDescriptor.Priority,
			}
		}
	}

	return nil

}

func (rule *R1004ExecFromMount) setMountPaths(podName string, namespace string, containerID string, containerName string, engineAccess EngineAccess) error {
	podSpec, err := engineAccess.GetPodSpec(podName, namespace, containerID)
	if err != nil {
		return fmt.Errorf("failed to get pod spec: %v", err)
	}

	mountPaths := []string{}
	for _, container := range podSpec.Containers {
		if container.Name == containerName {
			for _, volumeMount := range container.VolumeMounts {
				mountPaths = append(mountPaths, volumeMount.MountPath)
			}
		}
	}

	rule.mutex.Lock()
	defer rule.mutex.Unlock()
	rule.containerIdToMountPaths[containerID] = mountPaths

	return nil
}

func (rule *R1004ExecFromMount) isPathContained(targetpath, basepath string) bool {
	return strings.HasPrefix(targetpath, basepath)
}

func (rule *R1004ExecFromMount) Requirements() RuleRequirements {
	return RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.ExecveEventType},
		NeedApplicationProfile: false,
	}
}

func (rule *R1004ExecFromMountFailure) Name() string {
	return rule.RuleName
}

func (rule *R1004ExecFromMountFailure) Error() string {
	return rule.Err
}

func (rule *R1004ExecFromMountFailure) Event() tracing.GeneralEvent {
	return rule.FailureEvent.GeneralEvent
}

func (rule *R1004ExecFromMountFailure) Priority() int {
	return rule.RulePriority
}

func (rule *R1004ExecFromMountFailure) FixSuggestion() string {
	return rule.FixSuggestionMsg
}
