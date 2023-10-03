package engine

import (
	"log"

	"github.com/armosec/kubecop/pkg/ebpf/collector"
)

type Engine struct {
	dynamicApplicationProfiles  collector.ApplicationProfiles
	existingApplicationProfiles collector.ApplicationProfiles
}

func NewEngine() *Engine {
	return &Engine{
		dynamicApplicationProfiles:  make(collector.ApplicationProfiles),
		existingApplicationProfiles: make(collector.ApplicationProfiles),
	}
}

func (engine *Engine) Start() {
	for {
		for appProfileName, profile := range engine.dynamicApplicationProfiles {
			log.Printf("Application profile %v is: \n", appProfileName)
			for containerName, containerProfile := range profile.Containers {
				log.Printf("%v syscalls are: %v\n", containerName, containerProfile.SysCalls)
			}
		}
	}
}
