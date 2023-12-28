package scan

import "fmt"

type ClamAVConfig struct {
	Host         string
	Port         string
	ScanInterval int
}

func (c *ClamAVConfig) Address() string {
	return fmt.Sprintf("tcp://%s:%s", c.Host, c.Port)
}
