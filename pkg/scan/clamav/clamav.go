package clamav

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/armosec/kubecop/pkg/exporters"
	"github.com/armosec/kubecop/pkg/scan"
	humanize "github.com/dustin/go-humanize"
	"github.com/dutchcoders/go-clamd"
	"github.com/kubescape/kapprofiler/pkg/tracing"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type ClamAV struct {
	clamd                      *clamd.Clamd
	scanInterval               string
	scanLock                   sync.Mutex
	retryDelay                 time.Duration
	maxRetries                 int
	containeridToContainer     map[string]tracing.ContainerActivityEvent
	containeridToContainerLock sync.RWMutex
	exporterBus                *exporters.ExporterBus
}

type MalwareK8sData struct {
	// ContainerID of the container that was infected
	ContainerID string `json:"container_id"`
	// OverlayLayer of the container that was infected
	OverlayLayer string `json:"overlay_layer"`
}

// New ClamAV
func NewClamAV(config ClamAVConfig) *ClamAV {
	clamd := clamd.NewClamd(config.Address())

	return &ClamAV{
		clamd:                      clamd,
		scanInterval:               config.ScanInterval,
		scanLock:                   sync.Mutex{},
		retryDelay:                 config.RetryDelay,
		maxRetries:                 config.MaxRetries,
		containeridToContainer:     make(map[string]tracing.ContainerActivityEvent),
		containeridToContainerLock: sync.RWMutex{},
		exporterBus:                config.ExporterBus,
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
				c.scanLock.Lock()
				log.Printf("Starting scan of %s\n", path)
				c.scanWithRetries(ctx, path)
				c.scanLock.Unlock()
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
				// A malware was found, send an alert.
				hash, err := c.calculateFileHash(result.Path)
				if err != nil {
					log.Printf("Error calculating hash of %s: %v\n", result.Path, err)
				}
				size, err := c.getFileSize(result.Path)
				if err != nil {
					log.Printf("Error getting size of %s: %v\n", result.Path, err)
				}
				path := strings.TrimPrefix(result.Path, os.Getenv("HOST_ROOT"))
				malwareDescription := scan.MalwareDescription{
					Name:        result.Description,
					Path:        path,
					Hash:        hash,
					Size:        humanize.IBytes(uint64(size)),
					Description: result.Description,
				}

				malwareK8sData := c.getMalwarek8sData(path)
				if malwareK8sData.ContainerID == "" {
					log.Printf("Could not find container for path %s\n", path)
					log.Println("Malware is part of the host filesystem, sending alert without container details")
					c.exporterBus.SendMalwareAlert(malwareDescription)
					continue
				}

				// Get the container details.
				malwareDescription.PodName = c.containeridToContainer[malwareK8sData.ContainerID].PodName
				malwareDescription.Namespace = c.containeridToContainer[malwareK8sData.ContainerID].Namespace
				malwareDescription.Resource = schema.GroupVersionResource{
					Group:    "v1",
					Version:  "Pod",
					Resource: "Pod",
				}
				malwareDescription.ContainerName = c.containeridToContainer[malwareK8sData.ContainerID].ContainerName
				malwareDescription.ContainerID = malwareK8sData.ContainerID
				if malwareK8sData.OverlayLayer == "lower" {
					malwareDescription.IsPartOfImage = true
				} else {
					malwareDescription.IsPartOfImage = false
				}

				c.exporterBus.SendMalwareAlert(malwareDescription)
			}
		case <-ctx.Done():
			// The context was cancelled, which means we should stop the scan.
			log.Println("Scan cancelled")
			return ctx.Err()
		}
	}
}

func (c *ClamAV) OnContainerActivityEvent(event *tracing.ContainerActivityEvent) {
	switch event.Activity {
	case tracing.ContainerActivityEventStart:
		// Add the container to the map.
		c.containeridToContainerLock.Lock()
		c.containeridToContainer[event.ContainerID] = *event
		c.containeridToContainerLock.Unlock()
	case tracing.ContainerActivityEventAttached:
		// Add the container to the map.
		c.containeridToContainerLock.Lock()
		c.containeridToContainer[event.ContainerID] = *event
		c.containeridToContainerLock.Unlock()
	case tracing.ContainerActivityEventStop:
		// Remove the container from the map.
		c.containeridToContainerLock.Lock()
		delete(c.containeridToContainer, event.ContainerID)
		c.containeridToContainerLock.Unlock()
	}
}

// Iterate over /proc/<pid>/mountinfo files to find the container that contains the given path.
func (c *ClamAV) getMalwarek8sData(path string) MalwareK8sData {
	// Iterate over all containers.
	c.containeridToContainerLock.RLock()
	for _, container := range c.containeridToContainer {
		// Check if the path is in the container.
		overlayLayer := scan.GetOverlayLayer(path, container.Pid)
		if overlayLayer != "" {
			// The path is in the container, return the container ID.
			c.containeridToContainerLock.RUnlock()
			return MalwareK8sData{
				ContainerID:  container.ContainerID,
				OverlayLayer: overlayLayer,
			}
		}
	}
	c.containeridToContainerLock.RUnlock()

	return MalwareK8sData{}
}

// Get the size of the given file.
func (c *ClamAV) getFileSize(path string) (int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}

	// Get the file size.
	fileInfo, err := file.Stat()
	if err != nil {
		return 0, err
	}

	return fileInfo.Size(), nil
}

// Calculate the SHA256 hash of the given file.
func (c *ClamAV) calculateFileHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	hashInBytes := hash.Sum(nil)
	hashString := hex.EncodeToString(hashInBytes)

	return hashString, nil
}

// Ping ClamAV
func (c *ClamAV) Ping() error {
	return c.clamd.Ping()
}
