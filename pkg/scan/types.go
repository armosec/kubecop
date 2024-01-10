package scan

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type MalwareDescription struct {
	// Name of the malware
	Name string `json:"malware_name"`
	// Description of the malware
	Description string `json:"description"`
	// Path to the file that was infected
	Path string `json:"path"`
	// Hash of the file that was infected
	Hash string `json:"hash"`
	// Size of the file that was infected
	Size string `json:"size"`
	// Is part of the image
	IsPartOfImage bool `json:"is_part_of_image"`
	// K8s resource that was infected
	Resource schema.GroupVersionResource `json:"resource"`
	// K8s namespace that was infected
	Namespace string `json:"namespace"`
	// K8s pod that was infected
	PodName string `json:"kind"`
	// K8s container that was infected
	ContainerName string `json:"container_name"`
	// K8s container ID that was infected
	ContainerID string `json:"container_id"`
	// K8s container image that was infected
	ContainerImage string `json:"container_image"`
}
