package scan

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/kubernetes"
)

// GetContainerImageID returns the image ID of the given container in the given pod.
func GetContainerImageID(clientset *kubernetes.Clientset, namespace, podName, containerName string) (string, error) {
	pod, err := clientset.CoreV1().Pods(namespace).Get(context.Background(), podName, metav1.GetOptions{})
	if err != nil {
		fmt.Printf("Error getting pod: %v\n", err)
		return "", err
	}

	for _, container := range pod.Spec.Containers {
		if container.Name == containerName {
			return container.Image, nil
		}
	}

	return "", fmt.Errorf("could not find container %s in pod %s", containerName, podName)
}
