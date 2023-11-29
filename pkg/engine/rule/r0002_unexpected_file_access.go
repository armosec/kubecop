package rule

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

const (
	R0002ID                           = "R0002"
	R0002UnexpectedFileAccessRuleName = "Unexpected file access"
)

var R0002UnexpectedFileAccessRuleDescriptor = RuleDesciptor{
	ID:          R0002ID,
	Name:        R0002UnexpectedFileAccessRuleName,
	Description: "Detecting file access that are not whitelisted by application profile. File access is defined by the combination of path and flags",
	Tags:        []string{"open", "whitelisted"},
	Priority:    5,
	Requirements: RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.OpenEventType},
		NeedApplicationProfile: true,
	},
	RuleCreationFunc: func() Rule {
		return CreateRuleR0002UnexpectedFileAccess()
	},
}

type R0002UnexpectedFileAccess struct {
	BaseRule
	shouldIgnoreMounts bool
	// Map of container ID to mount paths
	mutex                   sync.RWMutex
	containerIdToMountPaths map[string][]string
}

type R0002UnexpectedFileAccessFailure struct {
	RuleName     string
	RulePriority int
	Err          string
	FailureEvent *tracing.OpenEvent
}

func (rule *R0002UnexpectedFileAccess) Name() string {
	return R0002UnexpectedFileAccessRuleName
}

func CreateRuleR0002UnexpectedFileAccess() *R0002UnexpectedFileAccess {
	return &R0002UnexpectedFileAccess{
		containerIdToMountPaths: map[string][]string{},
		shouldIgnoreMounts:      false,
	}
}

func (rule *R0002UnexpectedFileAccess) SetParameters(parameters map[string]interface{}) {
	rule.BaseRule.SetParameters(parameters)
	rule.shouldIgnoreMounts = fmt.Sprintf("%v", rule.GetParameters()["ignoreMounts"]) == "true"
}

func (rule *R0002UnexpectedFileAccess) DeleteRule() {
}

func (rule *R0002UnexpectedFileAccess) ProcessEvent(eventType tracing.EventType, event interface{}, appProfileAccess approfilecache.SingleApplicationProfileAccess, engineAccess EngineAccess) RuleFailure {
	if eventType != tracing.OpenEventType {
		return nil
	}

	openEvent, ok := event.(*tracing.OpenEvent)
	if !ok {
		return nil
	}

	if rule.shouldIgnoreMounts {
		rule.mutex.RLock()
		mounts, ok := rule.containerIdToMountPaths[openEvent.ContainerID]
		rule.mutex.RUnlock()
		if !ok {
			err := rule.setMountPaths(openEvent.PodName, openEvent.Namespace, openEvent.ContainerID, openEvent.ContainerName, engineAccess)
			if err != nil {
				log.Printf("Failed to set mount paths: %v", err)
				return nil
			}
			rule.mutex.RLock()
			mounts = rule.containerIdToMountPaths[openEvent.ContainerID]
			rule.mutex.RUnlock()
		}

		for _, mount := range mounts {
			contained := isPathContained(mount, openEvent.PathName)
			if contained {
				if os.Getenv("DEBUG") == "true" {
					log.Printf("Path %s is mounted in pod %s/%s - Skipping check", openEvent.PathName, openEvent.Namespace, openEvent.PodName)
				}
				return nil
			}
		}
	}

	if appProfileAccess == nil {
		return &R0002UnexpectedFileAccessFailure{
			RuleName:     rule.Name(),
			Err:          "Application profile is missing",
			FailureEvent: openEvent,
			RulePriority: RulePrioritySystemIssue,
		}
	}

	appProfileOpenList, err := appProfileAccess.GetOpenList()
	if err != nil || appProfileOpenList == nil {
		return &R0002UnexpectedFileAccessFailure{
			RuleName:     rule.Name(),
			Err:          "Application profile is missing",
			FailureEvent: openEvent,
			RulePriority: RulePrioritySystemIssue,
		}
	}

	for _, open := range *appProfileOpenList {
		if open.Path == openEvent.PathName {
			found := 0
			for _, eventOpenFlag := range openEvent.Flags {
				// Check that event open flag is in the open.Flags
				for _, profileOpenFlag := range open.Flags {
					if eventOpenFlag == profileOpenFlag {
						found += 1
					}
				}
			}
			if found == len(openEvent.Flags) {
				return nil
			}
			// TODO: optimize this list (so path will be only once in the list so we can break the loop)
		}
	}

	return &R0002UnexpectedFileAccessFailure{
		RuleName:     rule.Name(),
		Err:          fmt.Sprintf("Unexpected file access: %s with flags %v", openEvent.PathName, openEvent.Flags),
		FailureEvent: openEvent,
		RulePriority: R0002UnexpectedFileAccessRuleDescriptor.Priority,
	}
}

func (rule *R0002UnexpectedFileAccess) setMountPaths(podName string, namespace string, containerID string, containerName string, engineAccess EngineAccess) error {
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

func isPathContained(basepath, targetpath string) bool {
	return strings.HasPrefix(targetpath, basepath)
}

func (rule *R0002UnexpectedFileAccess) Requirements() RuleRequirements {
	return RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.OpenEventType},
		NeedApplicationProfile: true,
	}
}

func (rule *R0002UnexpectedFileAccessFailure) Name() string {
	return rule.RuleName
}

func (rule *R0002UnexpectedFileAccessFailure) Error() string {
	return rule.Err
}

func (rule *R0002UnexpectedFileAccessFailure) Event() tracing.GeneralEvent {
	return rule.FailureEvent.GeneralEvent
}

func (rule *R0002UnexpectedFileAccessFailure) Priority() int {
	return rule.RulePriority
}
