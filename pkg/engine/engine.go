package engine

import (
	"log"
	"time"

	"github.com/armosec/kubecop/pkg/ebpf/collector"
)

type Engine struct {
	dynamicApplicationProfiles  collector.ApplicationProfiles
	existingApplicationProfiles collector.ApplicationProfiles
}

func NewEngine(dynamicApplicationProfiles collector.ApplicationProfiles) *Engine {
	return &Engine{
		dynamicApplicationProfiles:  dynamicApplicationProfiles,
		existingApplicationProfiles: make(collector.ApplicationProfiles), // TODO: get existing profiles from DB.
	}
}

// TODO: implement the engine logic.
func (engine *Engine) Start() {
	for {
		for appProfileName, profile := range engine.dynamicApplicationProfiles {
			log.Printf("Application profile %v is: \n", appProfileName)
			for _, containerProfile := range profile.Containers {
				log.Printf("%v syscalls are: %v\n", containerProfile.Name, containerProfile.SysCalls)
				log.Printf("%v files are: %v\n", containerProfile.Name, containerProfile.Opens)
				log.Printf("%v network is: %v\n", containerProfile.Name, containerProfile.NetworkActivity)
				log.Printf("%v capabilities are: %v\n", containerProfile.Name, containerProfile.Capabilities)
				log.Printf("%v execs are: %v\n", containerProfile.Name, containerProfile.Execs)
			}
		}

		time.Sleep(5 * time.Second)
	}
}
