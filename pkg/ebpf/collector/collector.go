package collector

import (
	"fmt"
	"log"
	"time"

	"github.com/kubescape/kapprofiler/pkg/tracing"

	"golang.org/x/exp/slices"
	"k8s.io/client-go/kubernetes"
)

func StartCollectorManager(config *CollectorManagerConfig) (*CollectorManager, error) {
	// Get Kubernetes client
	client, err := kubernetes.NewForConfig(config.K8sConfig)
	if err != nil {
		return nil, err
	}
	cm := &CollectorManager{
		containers:          make(map[ContainerId]*ContainerState),
		k8sClient:           client,
		applicationProfiles: config.ApplicationProfiles,
		config:              *config,
		eventSink:           config.EventSink,
		tracer:              config.Tracer,
	}

	// Setup container events listener
	cm.tracer.AddContainerActivityListener(cm)

	return cm, nil
}

func (cm *CollectorManager) StopCollectorManager() error {
	// Stop container events listener
	cm.tracer.RemoveContainerActivityListener(cm)

	return nil
}

func (cm *CollectorManager) ContainerStarted(id *ContainerId) {
	// Add container to map with running state set to true
	cm.containers[*id] = &ContainerState{
		running: true,
	}
	// Add a timer for collection of data from container events
	startContainerTimer(id, cm.config.Interval, cm.CollectContainerEvents)
}

func (cm *CollectorManager) ContainerStopped(id *ContainerId) {
	// Check if container is still running (is it in the map?)
	if _, ok := cm.containers[*id]; ok {
		// Turn running state to false
		cm.containers[*id].running = false
	}

	// Collect data from container events
	go cm.CollectContainerEvents(id)
}

func (cm *CollectorManager) CollectContainerEvents(id *ContainerId) {
	// Check if container is still running (is it in the map?)
	if _, ok := cm.containers[*id]; ok {
		// Collect data from container events
		execveEvents, err := cm.eventSink.GetExecveEvents(id.Namespace, id.PodName, id.Container)
		if err != nil {
			log.Printf("error getting execve events: %s\n", err)
			return
		}

		openEvents, err := cm.eventSink.GetOpenEvents(id.Namespace, id.PodName, id.Container)
		if err != nil {
			log.Printf("error getting open events: %s\n", err)
			return
		}

		syscallList, err := cm.tracer.PeekSyscallInContainer(id.NsMntId)
		if err != nil {
			log.Printf("error getting syscall list: %s\n", err)
			return
		}

		capabilitiesEvents, err := cm.eventSink.GetCapabilitiesEvents(id.Namespace, id.PodName, id.Container)
		if err != nil {
			log.Printf("error getting capabilities events: %s\n", err)
			return
		}

		dnsEvents, err := cm.eventSink.GetDnsEvents(id.Namespace, id.PodName, id.Container)
		if err != nil {
			log.Printf("error getting dns events: %s\n", err)
			return
		}

		networkEvents, err := cm.eventSink.GetNetworkEvents(id.Namespace, id.PodName, id.Container)
		if err != nil {
			log.Printf("error getting network events: %s\n", err)
			return
		}

		// If there are no events, return
		if len(networkEvents) == 0 && len(dnsEvents) == 0 && len(execveEvents) == 0 && len(openEvents) == 0 && len(syscallList) == 0 && len(capabilitiesEvents) == 0 {
			return
		}

		containerProfile := ContainerProfile{Name: id.Container}

		// Add syscalls to container profile
		containerProfile.SysCalls = append(containerProfile.SysCalls, syscallList...)

		// Add execve events to container profile
		for _, event := range execveEvents {
			// TODO: check if event is already in containerProfile.Execs
			containerProfile.Execs = append(containerProfile.Execs, ExecCalls{
				Path: event.PathName,
				Args: event.Args,
				Envs: event.Env,
			})
		}

		// Add dns events to container profile
		for _, event := range dnsEvents {
			if !dnsEventExists(event, containerProfile.Dns) {
				containerProfile.Dns = append(containerProfile.Dns, DnsCalls{
					DnsName:   event.DnsName,
					Addresses: event.Addresses,
				})
			}
		}

		//interstingCapabilities := []string{"setpcap", "sysmodule", "net_raw", "net_admin", "sys_admin", "sys_rawio", "sys_ptrace", "sys_boot", "mac_override", "mac_admin", "perfmon", "all", "bpf"}
		// Add capabilities events to container profile
		for _, event := range capabilitiesEvents {
			// TODO: check if event is already in containerProfile.Capabilities
			//if slices.Contains(interstingCapabilities, event.CapabilityName) {
			if len(containerProfile.Capabilities) == 0 {
				containerProfile.Capabilities = append(containerProfile.Capabilities, CapabilitiesCalls{
					Capabilities: []string{event.CapabilityName},
					Syscall:      event.Syscall,
				})
			} else {
				for _, capability := range containerProfile.Capabilities {
					if capability.Syscall == event.Syscall {
						if !slices.Contains(capability.Capabilities, event.CapabilityName) {
							capability.Capabilities = append(capability.Capabilities, event.CapabilityName)
						}
					} else {
						var syscalls []string
						for _, cap := range containerProfile.Capabilities {
							syscalls = append(syscalls, cap.Syscall)
						}
						if !slices.Contains(syscalls, event.Syscall) {
							containerProfile.Capabilities = append(containerProfile.Capabilities, CapabilitiesCalls{
								Capabilities: []string{event.CapabilityName},
								Syscall:      event.Syscall,
							})
						}
					}
				}
			}
		}

		// Add open events to container profile
		for _, event := range openEvents {
			hasSameFile, hasSameFlags := openEventExists(event, containerProfile.Opens)
			// TODO: check if event is already in containerProfile.Opens & remove the 10000 limit.
			if len(containerProfile.Opens) < 10000 && !(hasSameFile && hasSameFlags) {
				openEvent := OpenCalls{
					Path:  event.PathName,
					Flags: event.Flags,
				}
				containerProfile.Opens = append(containerProfile.Opens, openEvent)
			}
		}

		// Add network activity to container profile
		var outgoingConnections []NetworkCalls
		var incomingConnections []NetworkCalls
		for _, networkEvent := range networkEvents {
			if networkEvent.PacketType == "OUTGOING" {
				if !networkEventExists(networkEvent, outgoingConnections) {
					outgoingConnections = append(outgoingConnections, NetworkCalls{
						Protocol:    networkEvent.Protocol,
						Port:        networkEvent.Port,
						DstEndpoint: networkEvent.DstEndpoint,
					})
				}
			} else if networkEvent.PacketType == "HOST" {
				if !networkEventExists(networkEvent, incomingConnections) {
					incomingConnections = append(incomingConnections, NetworkCalls{
						Protocol:    networkEvent.Protocol,
						Port:        networkEvent.Port,
						DstEndpoint: networkEvent.DstEndpoint,
					})
				}
			}
		}

		containerProfile.NetworkActivity = NetworkActivity{
			Incoming: incomingConnections,
			Outgoing: outgoingConnections,
		}

		// The name of the ApplicationProfile you're looking for.
		appProfileName := fmt.Sprintf("pod-%s", id.PodName)
		appProfile, ok := cm.applicationProfiles[appProfileName]

		if !ok {
			// it does not exist, create it.
			cm.applicationProfiles[appProfileName] = ApplicationProfile{
				Name:       appProfileName,
				Containers: []ContainerProfile{containerProfile},
			}
		} else {
			// it exists, add container profile diff to the existing container.
			containerExists := false
			for existingContainerIndex, existingContainerProfile := range appProfile.Containers {
				if existingContainerProfile.Name == id.Container {
					containerExists = true
					cm.applicationProfiles[appProfileName].Containers[existingContainerIndex] = containerProfile
					break
				}
			}

			if !containerExists {
				appProfile.Containers = append(appProfile.Containers, containerProfile)
				cm.applicationProfiles[appProfileName] = appProfile
			}
		}
	}

	// Restart timer
	startContainerTimer(id, cm.config.Interval, cm.CollectContainerEvents)
}

// Timer function
func startContainerTimer(id *ContainerId, seconds uint64, callback func(id *ContainerId)) *time.Timer {
	timer := time.NewTimer(time.Duration(seconds) * time.Second)

	// This goroutine waits for the timer to finish.
	go func() {
		<-timer.C
		callback(id)
	}()

	return timer
}

func (cm *CollectorManager) OnContainerActivityEvent(event *tracing.ContainerActivityEvent) {
	if event.Activity == tracing.ContainerActivityEventStart {
		cm.ContainerStarted(&ContainerId{
			Namespace:   event.Namespace,
			PodName:     event.PodName,
			Container:   event.ContainerName,
			NsMntId:     event.NsMntId,
			ContainerID: event.ContainerID,
		})
	} else if event.Activity == tracing.ContainerActivityEventStop {
		cm.ContainerStopped(&ContainerId{
			Namespace:   event.Namespace,
			PodName:     event.PodName,
			Container:   event.ContainerName,
			NsMntId:     event.NsMntId,
			ContainerID: event.ContainerID,
		})
	}
}

func networkEventExists(networkEvent *tracing.NetworkEvent, networkCalls []NetworkCalls) bool {
	for _, call := range networkCalls {
		if networkEvent.DstEndpoint == call.DstEndpoint && networkEvent.Port == call.Port && networkEvent.Protocol == call.Protocol {
			return true
		}
	}

	return false
}

func dnsEventExists(dnsEvent *tracing.DnsEvent, dnsCalls []DnsCalls) bool {
	for _, call := range dnsCalls {
		if dnsEvent.DnsName == call.DnsName {
			for _, address := range dnsEvent.Addresses {
				if !slices.Contains(call.Addresses, address) {
					call.Addresses = append(call.Addresses, address)
					log.Print("Event exists, appending missing address")
				}
			}

			return true
		}
	}

	return false
}

func openEventExists(openEvent *tracing.OpenEvent, openEvents []OpenCalls) (bool, bool) {
	hasSamePath := false
	hasSameFlags := false
	for _, element := range openEvents {
		if element.Path == openEvent.PathName {
			hasSamePath = true
			hasAllFlags := true
			for _, flag := range openEvent.Flags {
				// Check if flag is in the flags of the openEvent
				hasFlag := false
				for _, flag2 := range element.Flags {
					if flag == flag2 {
						hasFlag = true
						break
					}
				}
				if !hasFlag {
					hasAllFlags = false
					break
				}
			}
			if hasAllFlags {
				hasSameFlags = true
				break
			}
		}
		if hasSamePath && hasSameFlags {
			break
		}
	}

	return hasSamePath, hasSameFlags
}
