package clamav

import (
	"fmt"
	"time"

	"github.com/armosec/kubecop/pkg/exporters"
	"k8s.io/client-go/kubernetes"
)

type ClamAVConfig struct {
	Host             string
	Port             string
	ScanInterval     string
	RetryDelay       time.Duration
	MaxRetries       int
	ExporterBus      *exporters.ExporterBus
	KubernetesClient *kubernetes.Clientset
}

func (c *ClamAVConfig) Address() string {
	return fmt.Sprintf("tcp://%s:%s", c.Host, c.Port)
}
