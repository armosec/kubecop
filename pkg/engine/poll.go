package engine

import (
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/kubescape/kapprofiler/pkg/tracing"
)

// Function to start pull componet from tracer
func (engine *Engine) StartPullComponent() {
	if !engine.pollLoopRunning {
		if engine.tracer != nil {
			engine.pollLoopCancelChannel = make(chan struct{})
			go engine.Poll()
		} else {
			log.Printf("Tracer not initialized, ignoring request to start poll loop\n")
		}
	} else {
		log.Printf("Poll loop already running, ignoring request to start it again\n")
	}
}

// Function to stop pull componet from tracer
func (engine *Engine) StopPullComponent() {
	if engine.pollLoopRunning {
		close(engine.pollLoopCancelChannel)
		engine.pollLoopRunning = false
	} else {
		log.Printf("Poll loop not running, ignoring request to stop it\n")
	}
}

func cancelableSleep(d time.Duration, cancel <-chan struct{}) error {
	select {
	case <-time.After(d):
		return nil
	case <-cancel:
		return fmt.Errorf("sleep canceled")
	}
}

// Function main poll loop
func (engine *Engine) Poll() {
	engine.pollLoopRunning = true
	for {
		if cancelableSleep(1*time.Second, engine.pollLoopCancelChannel) == nil {
			// Time elapsed without cancelation, do the work
			if engine.tracer != nil {
				// Loop over the containerIdToDetailsCache map
				for containerId, containerDetails := range getcontainerIdToDetailsCacheCopy() {
					syscalls, err := engine.tracer.PeekSyscallInContainer(containerDetails.NsMntId)
					if err != nil {
						continue
					}
					// Generate events for the syscalls and process them in the engine
					e := tracing.SyscallEvent{
						GeneralEvent: tracing.GeneralEvent{
							ContainerID:   containerId,
							ContainerName: containerDetails.ContainerName,
							PodName:       containerDetails.PodName,
							Namespace:     containerDetails.Namespace,
							Timestamp:     time.Now().UnixNano(),
						},
						Syscalls: syscalls,
					}
					engine.submitEventForProcessing(containerId, tracing.SyscallEventType, &e)
				}
			}
		}
	}
}
