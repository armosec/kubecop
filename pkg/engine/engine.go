package engine

import (
	"log"
	"time"

	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/armosec/kubecop/pkg/ebpf/collector"
	"github.com/armosec/kubecop/pkg/engine/rule"
	"golang.org/x/exp/slices"
)

type Engine struct {
	applicationProfileCache    approfilecache.ApplicationProfileCache
	containerProfileToRulesMap map[string][]rule.IRule // String is the container profile name.
	shouldStop                 bool
}

func NewEngine(appProfileCache approfilecache.ApplicationProfileCache) *Engine {
	return &Engine{
		applicationProfileCache:    appProfileCache,
		containerProfileToRulesMap: make(map[string][]rule.IRule),
		shouldStop:                 false,
	}
}

// RegisterRulesForContainerProfile registers the needed rules for the given container profile.
func (engine *Engine) registerRulesForContainerProfile(containerProfileName string) {
	rules := rule.CreateRules()
	engine.containerProfileToRulesMap[containerProfileName] = append(engine.containerProfileToRulesMap[containerProfileName], rules...)
}

// Stream events from the collector and apply the rules on them.
func (engine *Engine) streamEventsToRules(containerProfile collector.ContainerProfile) {
	for _, rule := range engine.containerProfileToRulesMap[containerProfile.Name] {
		// Each rule has a different set of needed events. We need to filter the events from the collector by the needed events of the rule.
		// TODO: implement the filtering and the streaming.
		log.Printf("Streaming events to rule %v\n", rule.Name())
	}
}

func (engine *Engine) Stop() {
	engine.shouldStop = true
}

// Clears the rules of the containers that are not running anymore.
func (engine *Engine) clearNotRunningContainers() {
	existingContainerProfilesNames := make([]string, len(engine.containerProfileToRulesMap))
	for containerProfileName := range engine.containerProfileToRulesMap {
		existingContainerProfilesNames = append(existingContainerProfilesNames, containerProfileName)
	}

	var runningContainerNames []string

	for _, profile := range engine.dynamicApplicationProfiles {
		for _, containerProfile := range profile.Containers {
			runningContainerNames = append(runningContainerNames, containerProfile.Name)
		}
	}

	for _, containerProfileName := range existingContainerProfilesNames {
		if !slices.Contains(runningContainerNames, containerProfileName) {
			log.Printf("Removing %v from container profiles\n", containerProfileName)
			delete(engine.containerProfileToRulesMap, containerProfileName)
		}
	}

}

func (engine *Engine) Start() {
	// Run while the engine should not stop.
	for !engine.shouldStop {
		// Start by clearing the rules of the containers that are not running anymore.
		engine.clearNotRunningContainers()

		// Register and Stream events to the rules of the dynamic application profiles.
		for _, profile := range engine.dynamicApplicationProfiles {
			for _, containerProfile := range profile.Containers {
				if _, ok := engine.containerProfileToRulesMap[containerProfile.Name]; !ok {
					engine.registerRulesForContainerProfile(containerProfile.Name)
				}

				engine.streamEventsToRules(containerProfile)
			}
		}

		time.Sleep(25 * time.Second)
	}
	// for {
	// 	for appProfileName, profile := range engine.dynamicApplicationProfiles {
	// 		log.Printf("Application profile %v is: \n", appProfileName)
	// 		for _, containerProfile := range profile.Containers {
	// 			log.Printf("%v execs are: %v\n", containerProfile.Name, containerProfile.Execs)
	// 		}
	// 	}

	// 	time.Sleep(5 * time.Second)
	// }
}
