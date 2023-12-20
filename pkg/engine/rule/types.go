package rule

import (
	corev1 "k8s.io/api/core/v1"
)

type Action string

const (
	KillPodAction     Action = "kill_pod"
	KillProcessAction Action = "kill_process"
	NoAction          Action = "no_action"
)

type EngineAccess interface {
	GetPodSpec(podName, namespace, containerID string) (*corev1.PodSpec, error)
	GetApiServerIpAddress() (string, error)
}
