package engine

import (
	"fmt"
	"sync"
	"time"

	"github.com/kubescape/kapprofiler/pkg/tracing"
)

type EngineStatePrinter interface {
	Print(v ...any)
}

type EngineStats struct {
	printer            EngineStatePrinter
	ebpfLock           sync.RWMutex
	ebpfEventStats     map[tracing.EventType]int
	ruleLock           sync.RWMutex
	ruleStats          map[string]int
	alertLock          sync.RWMutex
	alertStats         map[string]int
	stopChannel        chan struct{}
	collectionInterval time.Duration
}

func CreateStatComponent(printer EngineStatePrinter, collectionInterval time.Duration) *EngineStats {
	// Start a goroutine that will periodically print the stats
	// Create a channel that will be used to stop the goroutine
	engine := EngineStats{stopChannel: make(chan struct{}),
		printer:            printer,
		ebpfEventStats:     make(map[tracing.EventType]int),
		ruleStats:          make(map[string]int),
		alertStats:         make(map[string]int),
		collectionInterval: collectionInterval,
	}

	go engine.StatProcessing()
	return &engine
}

func (e *EngineStats) DestroyStatComponent() {
	close(e.stopChannel)
}

func (e *EngineStats) StatProcessing() {
	for {
		select {
		case <-e.stopChannel:
			return
		case <-time.After(e.collectionInterval):
			// Copy the maps then clear them
			ebpfEventStatsCopy := make(map[tracing.EventType]int)
			ruleStatsCopy := make(map[string]int)
			alertStatsCopy := make(map[string]int)
			e.ebpfLock.RLock()
			for k, v := range e.ebpfEventStats {
				ebpfEventStatsCopy[k] = v
			}
			e.ebpfLock.RUnlock()
			e.ruleLock.RLock()
			for k, v := range e.ruleStats {
				ruleStatsCopy[k] = v
			}
			e.ruleLock.RUnlock()
			e.alertLock.RLock()
			for k, v := range e.alertStats {
				alertStatsCopy[k] = v
			}
			e.alertLock.RUnlock()
			e.ebpfEventStats = make(map[tracing.EventType]int)
			e.ruleStats = make(map[string]int)
			e.alertStats = make(map[string]int)

			// Convert interval to human readable string
			intervalString := e.collectionInterval.String()
			text := fmt.Sprintf("Engine processing stats (per %s):\n", intervalString)
			text += "EBPF events:\n"
			for k, v := range ebpfEventStatsCopy {
				eventString := ""
				switch k {
				case tracing.ExecveEventType:
					eventString = "Execve"
				case tracing.OpenEventType:
					eventString = "Open"
				case tracing.NetworkEventType:
					eventString = "Network"
				case tracing.CapabilitiesEventType:
					eventString = "Capabilities"
				case tracing.DnsEventType:
					eventString = "DNS"
				case tracing.SyscallEventType:
					eventString = "Syscall"
				}
				text += fmt.Sprintf("\t%s: %d\n", eventString, v)
			}
			if len(ruleStatsCopy) > 0 {
				text += "Rules processed:\n"
				for k, v := range ruleStatsCopy {
					text += fmt.Sprintf("\t%s: %d\n", k, v)
				}
			} else {
				text += "No rules processed\n"
			}
			if len(alertStatsCopy) > 0 {
				text += "Alerts fired:\n"
				for k, v := range alertStatsCopy {
					text += fmt.Sprintf("\t%s: %d\n", k, v)
				}
			} else {
				text += "No alerts fired\n"
			}
			e.printer.Print(text)
		}
	}
}

func (e *EngineStats) ReportEbpfEvent(eventType tracing.EventType) {
	// Check if eventType exists in map
	e.ebpfLock.Lock()
	if _, ok := e.ebpfEventStats[eventType]; !ok {
		// Create it
		e.ebpfEventStats[eventType] = 0
	}
	// Lock the map
	e.ebpfEventStats[eventType]++
	e.ebpfLock.Unlock()
}

func (e *EngineStats) ReportRuleProcessed(ruleID string) {
	// Check if ruleID exists in map
	e.ruleLock.Lock()
	if _, ok := e.ruleStats[ruleID]; !ok {
		// Create it
		e.ruleStats[ruleID] = 0
	}
	e.ruleStats[ruleID]++
	e.ruleLock.Unlock()
}

func (e *EngineStats) ReportRuleAlereted(ruleID string) {
	// Check if ruleID exists in map
	e.alertLock.Lock()
	if _, ok := e.alertStats[ruleID]; !ok {
		// Create it
		e.alertStats[ruleID] = 0
	}
	e.alertStats[ruleID]++
	e.alertLock.Unlock()
}
