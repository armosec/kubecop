package clamav

import "fmt"

type ClamAVConfig struct {
	Host         string
	Port         string
	ScanInterval string
}

func (c *ClamAVConfig) Address() string {
	return fmt.Sprintf("tcp://%s:%s", c.Host, c.Port)
}
