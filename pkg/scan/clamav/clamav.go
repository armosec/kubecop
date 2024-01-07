package clamav

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/armosec/kubecop/pkg/exporters"
	"github.com/armosec/kubecop/pkg/scan"
	"github.com/dutchcoders/go-clamd"
)

type ClamAV struct {
	clamd        *clamd.Clamd
	scanInterval string
	mutex        sync.Mutex
	retryDelay   time.Duration
	maxRetries   int
}

// New ClamAV
func NewClamAV(config ClamAVConfig) *ClamAV {
	clamd := clamd.NewClamd(config.Address())

	return &ClamAV{
		clamd:        clamd,
		scanInterval: config.ScanInterval,
		mutex:        sync.Mutex{},
		retryDelay:   config.RetryDelay,
		maxRetries:   config.MaxRetries,
	}
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
				c.mutex.Lock()
				log.Printf("Starting scan of %s\n", path)
				c.scanWithRetries(ctx, path)
				c.mutex.Unlock()
			}

			// Parse the given interval
			interval, err := time.ParseDuration(c.scanInterval)
			if err != nil {
				log.Fatal(err)
			}

			// Wait for the given interval before scanning again
			time.Sleep(interval)
		}
	}()
}

// scanWithRetries attempts to scan the given path with retries on failure.
func (c *ClamAV) scanWithRetries(ctx context.Context, path string) {
	for retry := 0; retry <= c.maxRetries; retry++ {
		err := c.scan(ctx, path)
		if err == nil {
			// Scan succeeded, break out of the retry loop.
			break
		}

		log.Printf("Error during scan attempt %d: %v", retry+1, err)

		select {
		case <-ctx.Done():
			// The context was canceled, which means we should stop the scan.
			log.Println("Scan canceled")
			return
		case <-time.After(c.retryDelay):
			// Wait for the given delay before retrying the scan.
			continue
		}
	}
}

// Scan the given path for viruses (recursively).
func (c *ClamAV) scan(ctx context.Context, path string) error {
	response, err := c.clamd.ContScanFile(path)

	if err != nil {
		return err
	}

	for {
		select {
		case result, ok := <-response:
			if !ok {
				// The response channel was closed, which means the scan is over.
				log.Println("Scan completed")
				return nil
			}
			if result.Status == clamd.RES_FOUND {
				exporters.SendMalwareAlert(scan.MalwareDescription{
					Name:        result.Description,
					Path:        result.Path,
					Hash:        result.Hash,
					Size:        result.Size,
					Description: result.Description,
				})
			}
		case <-ctx.Done():
			// The context was cancelled, which means we should stop the scan.
			log.Println("Scan cancelled")
			return ctx.Err()
		}
	}
}

// Ping ClamAV
func (c *ClamAV) Ping() error {
	return c.clamd.Ping()
}
