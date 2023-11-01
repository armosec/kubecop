package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/armosec/kubecop/pkg/engine/rule"
	"github.com/kubescape/kapprofiler/pkg/tracing"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type containerEntry struct {
	ContainerName string
	PodName       string
	Namespace     string
	OwnerKind     string
	OwnerName     string
	// Low level container information
	NsMntId uint64

	// Add rules here
	BoundRules []rule.Rule
}

// Container ID to details cache
var containerIdToDetailsCache = make(map[string]containerEntry)

func (engine *Engine) OnContainerActivityEvent(event *tracing.ContainerActivityEvent) {
	if event.Activity == tracing.ContainerActivityEventStart {
		go func() {
			ownerRef, err := getHighestOwnerOfPod(engine.k8sClientset, event.PodName, event.Namespace)
			if err != nil {
				log.Printf("Failed to get highest owner of pod %s/%s: %v\n", event.Namespace, event.PodName, err)
				return
			}

			// Get the rules that are bound to the container
			// TODO do real binding implementation, right now we just get a single rule
			boundRules := rule.CreateRulesByNames([]string{rule.R0001ExecWhitelistedRuleDescriptor.Name})

			// Add the container to the cache
			containerIdToDetailsCache[event.ContainerID] = containerEntry{
				ContainerName: event.ContainerName,
				PodName:       event.PodName,
				Namespace:     event.Namespace,
				OwnerKind:     ownerRef.Kind,
				OwnerName:     ownerRef.Name,
				NsMntId:       event.NsMntId,
				BoundRules:    boundRules,
			}
		}()
	} else if event.Activity == tracing.ContainerActivityEventStop {
		go func() {
			// Remove the container from the cache
			delete(containerIdToDetailsCache, event.ContainerID)
		}()
	}
}

func (engine *Engine) GetWorkloadOwnerKindAndName(event tracing.GeneralEvent) (string, string, error) {
	eventContainerId := event.ContainerID
	if eventContainerId == "" {
		return "", "", fmt.Errorf("eventContainerId is empty")
	}
	// Get the container details from the cache
	containerDetails, ok := containerIdToDetailsCache[eventContainerId]
	if !ok {
		return "", "", fmt.Errorf("container details not found in cache")
	}
	return containerDetails.OwnerKind, containerDetails.OwnerName, nil
}

func (engine *Engine) GetRulesForEvent(event tracing.GeneralEvent) []rule.Rule {
	eventContainerId := event.ContainerID
	if eventContainerId == "" {
		return []rule.Rule{}
	}
	// Get the container details from the cache
	containerDetails, ok := containerIdToDetailsCache[eventContainerId]
	if !ok {
		return []rule.Rule{}
	}
	return containerDetails.BoundRules
}

// getHighestOwnerOfPod gets the highest owner of a pod in the given namespace.
func getHighestOwnerOfPod(clientset *kubernetes.Clientset, podName, namespace string) (metav1.OwnerReference, error) {
	var retOwner metav1.OwnerReference

	pod, err := clientset.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
	if err != nil {
		return retOwner, err
	}

	owner := pod.GetOwnerReferences()
	// Filter Node owner
	for i, ownerReference := range owner {
		if ownerReference.Kind == "Node" {
			owner = append(owner[:i], owner[i+1:]...)
		}
	}
	if len(owner) == 0 {
		// Return the Pod itself if it has no owner
		retOwner = metav1.OwnerReference{
			APIVersion: pod.APIVersion,
			Kind:       "Pod",
			Name:       pod.Name,
		}
		return retOwner, nil
	}

	// Traverse through owner references until we get the top owner
	for true {
		ownerReference := owner[0]
		// Get the Kubernetes object of the owner and check if it has an owner
		req := clientset.Discovery().RESTClient().Get().AbsPath(fmt.Sprintf("/apis/%s/namespaces/%s/%s/%s", ownerReference.APIVersion, namespace, strings.ToLower(ownerReference.Kind)+"s", ownerReference.Name))
		result := req.Do(context.TODO())
		ownerRaw, err := result.Raw()

		if err != nil {
			return retOwner, err
		}

		var ownerMap map[string]interface{}
		if err := json.Unmarshal(ownerRaw, &ownerMap); err != nil {
			return retOwner, err
		}

		// Check if the current owner has an owner itself
		if metadata, ok := ownerMap["metadata"].(map[string]interface{}); ok {
			if owners, ok := metadata["ownerReferences"].([]interface{}); ok {
				if len(owners) > 0 {
					// Use the first owner (if multiple)
					if ownerData, ok := owners[0].(map[string]interface{}); ok {
						nextOwner := metav1.OwnerReference{
							APIVersion: ownerData["apiVersion"].(string),
							Kind:       ownerData["kind"].(string),
							Name:       ownerData["name"].(string),
						}
						owner = []metav1.OwnerReference{nextOwner}
						continue
					}
				} else {
					// No owner, we have reached the top
					retOwner = owner[0]
					return retOwner, nil
				}
			} else {
				retOwner = owner[0]
				return retOwner, nil
			}
		} else {
			return retOwner, fmt.Errorf("metadata is not an object")
		}
	}
	return retOwner, nil
}
