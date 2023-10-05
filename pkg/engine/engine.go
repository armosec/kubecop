package engine

import (
	"context"
	"log"

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

	reverseShell := rule.NewReverseShellRule()
	err = reverseShell.GetFSM().Event(context.Background(), "syscall", "dup")
	if err != nil {
		reverseShell.GetFSM().Current()
		log.Printf("Error: %v\n State1: %v", err, reverseShell.GetFSM().Current())
	}
	err = reverseShell.GetFSM().Event(context.Background(), "syscall", "dup")
	if err != nil {
		log.Printf("Error: %v\n State2: %v", err, reverseShell.GetFSM().Current())
	}
	err = reverseShell.GetFSM().Event(context.Background(), "syscall", "bla")
	if err != nil {
		log.Printf("Error: %v\n State3: %v", err, reverseShell.GetFSM().Current())
	}
	err = reverseShell.GetFSM().Event(context.Background(), "syscall", "execve")
	if err != nil {
		log.Printf("Error: %v\n State: %v", err, reverseShell.GetFSM().Current())
	}
	err = reverseShell.GetFSM().Event(context.Background(), "syscall", "dup")
	if err != nil {
		reverseShell.GetFSM().Current()
		log.Printf("Error: %v\n State1: %v", err, reverseShell.GetFSM().Current())
	}
	err = reverseShell.GetFSM().Event(context.Background(), "syscall", "dup")
	if err != nil {
		log.Printf("Error: %v\n State2: %v", err, reverseShell.GetFSM().Current())
	}
	err = reverseShell.GetFSM().Event(context.Background(), "syscall", "dup")
	if err != nil {
		log.Printf("Error: %v\n State3: %v", err, reverseShell.GetFSM().Current())
	}
	err = reverseShell.GetFSM().Event(context.Background(), "syscall", "execve")
	if err != nil {
		log.Printf("Error: %v\n State: %v", err, reverseShell.GetFSM().Current())
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
