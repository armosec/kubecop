package clamav

import (
	"context"
	"log"
	"time"

	"github.com/armosec/kubecop/pkg/exporters"
	"github.com/armosec/kubecop/pkg/scan"
	"github.com/dutchcoders/go-clamd"
)

type ClamAV struct {
	clamd        *clamd.Clamd
	scanInterval string
}

// New ClamAV
func NewClamAV(config ClamAVConfig) *ClamAV {
	clamd := clamd.NewClamd(config.Address())

	return &ClamAV{clamd: clamd, scanInterval: config.ScanInterval}
}

func (c *ClamAV) StartInfiniteScan(ctx context.Context, path string) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				// The context was cancelled, which means we should stop the scan.
				log.Println("Infinite scan cancelled")
				return
			default:
				log.Println("Starting scan")
				c.scan(ctx, path)
			}

			// Convert c.scanInterval to time.Duration before multiplying with time.Second
			interval, err := time.ParseDuration(c.scanInterval)
			if err != nil {
				log.Fatal(err)
			}

			// Wait for the given interval before scanning again
			time.Sleep(interval)
		}
	}()
}

// Scan the given path for viruses (recursively).
func (c *ClamAV) scan(ctx context.Context, path string) {
	response, err := c.clamd.ContScanFile(path)

	if err != nil {
		log.Fatal(err)
	}

	for {
		select {
		case result, ok := <-response:
			if !ok {
				// The response channel was closed, which means the scan is over.
				log.Println("Scan completed")
				return
			}
			if result.Status == clamd.RES_FOUND {
				exporters.SendMalwareAlert(scan.MalwareDescription{})
			}
		case <-ctx.Done():
			// The context was cancelled, which means we should stop the scan.
			log.Println("Scan cancelled")
			return
		}
	}
}

// Ping ClamAV
func (c *ClamAV) Ping() error {
	return c.clamd.Ping()
}
