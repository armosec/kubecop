package clamav

import (
	"fmt"
	"time"
)

type ClamAVConfig struct {
	Host         string
	Port         string
	ScanInterval string
	RetryDelay   time.Duration
	MaxRetries   int
}

func (c *ClamAVConfig) Address() string {
	return fmt.Sprintf("tcp://%s:%s", c.Host, c.Port)
}
