package engine

import (
	"context"
	"log"
	"time"

	"github.com/armosec/kubecop/pkg/ebpf/collector"
	"github.com/armosec/kubecop/pkg/engine/rule"
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
	exec := rule.NewNonWhitelistedExecRule()
	err := exec.GetFSM().Event(context.Background(), "exec", "bla")
	if err != nil {
		log.Printf("Error: %v\n", err)
	}
	for {
		for appProfileName, profile := range engine.dynamicApplicationProfiles {
			log.Printf("Application profile %v is: \n", appProfileName)
			for _, containerProfile := range profile.Containers {
				log.Printf("%v execs are: %v\n", containerProfile.Name, containerProfile.Execs)
			}
		}

		time.Sleep(5 * time.Second)
	}
}
