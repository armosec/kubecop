package scan

import (
	"context"
	"log"
	"time"

	"github.com/dutchcoders/go-clamd"
)

type ClamAV struct {
	clamd        *clamd.Clamd
	scanInterval int
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
				c.scan(ctx, path)
			}

			// Wait for the given interval before scanning again
			time.Sleep(time.Duration(c.scanInterval) * time.Second)
		}
	}()
}

// Continuously scan the given path for viruses (recursively).
func (c *ClamAV) scan(ctx context.Context, path string) {
	response, err := c.clamd.AllMatchScanFile(path)

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
				log.Printf("Virus detected: %s\nHash: %s\n Size: %d\n Path: %s", result.Description, result.Hash, result.Size, result.Path)
			} else if result.Status == clamd.RES_ERROR {
				log.Printf("error scanning file: %s", result.Description)
			} else if result.Status == clamd.RES_PARSE_ERROR {
				log.Printf("error parsing file: %s", result.Description)
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
