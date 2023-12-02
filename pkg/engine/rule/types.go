package rule

import (
	corev1 "k8s.io/api/core/v1"
)

type EngineAccess interface {
	GetPodSpec(podName, namespace, containerID string) (*corev1.PodSpec, error)
	GetApiServerIpAddress() (string, error)
}
