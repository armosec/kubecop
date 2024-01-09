package clamav

import (
	"fmt"
	"time"

	"github.com/armosec/kubecop/pkg/exporters"
)

type ClamAVConfig struct {
	Host         string
	Port         string
	ScanInterval string
	RetryDelay   time.Duration
	MaxRetries   int
	ExporterBus  *exporters.ExporterBus
}

func (c *ClamAVConfig) Address() string {
	return fmt.Sprintf("tcp://%s:%s", c.Host, c.Port)
}
