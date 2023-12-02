package engine

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (engine *Engine) fetchPodSpec(podName, namespace string) (*corev1.PodSpec, error) {
	pod, err := engine.k8sClientset.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	return &pod.Spec, nil
}

func (engine *Engine) GetApiServerIpAddress() (string, error) {
	service, err := engine.k8sClientset.CoreV1().Services("default").Get(context.Background(), "kubernetes", metav1.GetOptions{})
	if err != nil {
		return "", err
	}

	for _, ip := range service.Spec.ClusterIPs {
		return ip, nil
	}

	return "", fmt.Errorf("failed to get api server ip")
}
