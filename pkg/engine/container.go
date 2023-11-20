package engine

import (
	"context"
	"fmt"
	"log"

	"github.com/armosec/kubecop/pkg/engine/rule"
	"github.com/armosec/kubecop/pkg/rulebindingstore"
	"github.com/kubescape/kapprofiler/pkg/tracing"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func fullPodName(namespace, podName string) string {
	return namespace + "/" + podName
}

func (engine *Engine) OnRuleBindingChanged(ruleBinding rulebindingstore.RuntimeAlertRuleBinding) {
	log.Printf("OnRuleBindingChanged: %s\n", ruleBinding.Name)
	// list all namespaces which match the rule binding selectors
	nsList, err := engine.k8sClientset.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{
		LabelSelector: metav1.FormatLabelSelector(&ruleBinding.Spec.NamespaceSelector),
	})
	if err != nil {
		log.Printf("Failed to list namespaces: %v\n", err)
		return
	}
	podsMap := make(map[string]struct{})
	for _, ns := range nsList.Items {
		// list all pods in the namespace which match the rule binding selectors
		podList, err := engine.k8sClientset.CoreV1().Pods(ns.Name).List(context.TODO(), metav1.ListOptions{
			LabelSelector: metav1.FormatLabelSelector(&ruleBinding.Spec.PodSelector),
			FieldSelector: "spec.nodeName=" + engine.nodeName,
		})
		if err != nil {
			log.Printf("Failed to list pods in namespace %s: %v\n", ns.Name, err)
			continue
		}
		for _, pod := range podList.Items {
			podsMap[fullPodName(ns.Name, pod.Name)] = struct{}{}
		}
	}

	for _, det := range getcontainerIdToDetailsCacheCopy() {
		if _, ok := podsMap[fullPodName(det.Namespace, det.PodName)]; ok {
			go engine.associateRulesWithContainerInCache(det)
		}
	}
}

func (engine *Engine) OnContainerActivityEvent(event *tracing.ContainerActivityEvent) {
	if event.Activity == tracing.ContainerActivityEventStart {

		ownerRef, err := getHighestOwnerOfPod(engine.k8sClientset, event.PodName, event.Namespace)
		if err != nil {
			log.Printf("Failed to get highest owner of pod %s/%s: %v\n", event.Namespace, event.PodName, err)
			return
		}

		// Load application profile if it exists
		err = engine.applicationProfileCache.LoadApplicationProfile(event.Namespace, ownerRef.Kind, ownerRef.Name, event.ContainerName, event.ContainerID)
		if err != nil {
			// Ask cache to load the application profile when/if it becomes available
			err = engine.applicationProfileCache.AnticipateApplicationProfile(event.Namespace, ownerRef.Kind, ownerRef.Name, event.ContainerName, event.ContainerID)
			if err != nil {
				log.Printf("Failed to anticipate application profile for container %s/%s/%s/%s: %v\n", event.Namespace, ownerRef.Kind, ownerRef.Name, event.ContainerName, err)
			}
		}
		contEntry := containerEntry{
			ContainerID:   event.ContainerID,
			ContainerName: event.ContainerName,
			PodName:       event.PodName,
			Namespace:     event.Namespace,
			OwnerKind:     ownerRef.Kind,
			OwnerName:     ownerRef.Name,
			NsMntId:       event.NsMntId,
		}
		err = engine.associateRulesWithContainerInCache(contEntry)
		if err != nil {
			log.Printf("Failed to add container details to cache: %v\n", err)
		}

	} else if event.Activity == tracing.ContainerActivityEventStop {
		go func() {
			deleteContainerDetails(event.ContainerID)
		}()
	}
}

func (engine *Engine) associateRulesWithContainerInCache(contEntry containerEntry) error {

	// Get the rules that are bound to the container
	ruleNames, err := engine.getRulesForPodFunc(contEntry.PodName, contEntry.Namespace)
	if err != nil {
		return fmt.Errorf("failed to get rules for pod %s/%s: %v", contEntry.Namespace, contEntry.PodName, err)
	}
	if len(ruleNames) == 0 {
		return nil
	}
	boundRules := rule.CreateRulesByNames(ruleNames)
	contEntry.BoundRules = boundRules

	// Add the container to the cache
	setContainerDetails(contEntry.ContainerID, contEntry)
	return nil
}

func (engine *Engine) GetWorkloadOwnerKindAndName(event *tracing.GeneralEvent) (string, string, error) {
	eventContainerId := event.ContainerID
	if eventContainerId == "" {
		return "", "", fmt.Errorf("eventContainerId is empty")
	}
	// Get the container details from the cache
	containerDetails, ok := getContainerDetails(eventContainerId)
	if !ok {
		return "", "", fmt.Errorf("container details not found in cache")
	}
	return containerDetails.OwnerKind, containerDetails.OwnerName, nil
}

func (engine *Engine) GetRulesForEvent(event *tracing.GeneralEvent) []rule.Rule {
	eventContainerId := event.ContainerID
	if eventContainerId == "" {
		return []rule.Rule{}
	}
	// Get the container details from the cache
	containerDetails, ok := getContainerDetails(eventContainerId)
	if !ok {
		return []rule.Rule{}
	}
	return containerDetails.BoundRules
}

// getHighestOwnerOfPod gets the highest owner of a pod in the given namespace.
func getHighestOwnerOfPod(clientset ClientSetInterface, podName, namespace string) (metav1.OwnerReference, error) {
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
	for {
		ownerReference := owner[0]

		switch ownerReference.Kind {
		case "ReplicaSet":
			// Get the Kubernetes object of the owner and check if it has an owner
			rs, err := clientset.AppsV1().ReplicaSets(namespace).Get(context.TODO(), ownerReference.Name, metav1.GetOptions{})
			if err != nil {
				return retOwner, err
			}
			owner = rs.GetOwnerReferences()
		case "Deployment":
			// Get the Kubernetes object of the owner and check if it has an owner
			deployment, err := clientset.AppsV1().Deployments(namespace).Get(context.TODO(), ownerReference.Name, metav1.GetOptions{})
			if err != nil {
				return retOwner, err
			}
			owner = deployment.GetOwnerReferences()
		case "StatefulSet":
			// Get the Kubernetes object of the owner and check if it has an owner
			statefulset, err := clientset.AppsV1().StatefulSets(namespace).Get(context.TODO(), ownerReference.Name, metav1.GetOptions{})
			if err != nil {
				return retOwner, err
			}
			owner = statefulset.GetOwnerReferences()
		case "DaemonSet":
			// Get the Kubernetes object of the owner and check if it has an owner
			daemonset, err := clientset.AppsV1().DaemonSets(namespace).Get(context.TODO(), ownerReference.Name, metav1.GetOptions{})
			if err != nil {
				return retOwner, err
			}
			owner = daemonset.GetOwnerReferences()
		case "Job":
			// Get the Kubernetes object of the owner and check if it has an owner
			job, err := clientset.BatchV1().Jobs(namespace).Get(context.TODO(), ownerReference.Name, metav1.GetOptions{})
			if err != nil {
				return retOwner, err
			}
			owner = job.GetOwnerReferences()
		case "CronJob":
			// Get the Kubernetes object of the owner and check if it has an owner
			cronjob, err := clientset.BatchV1().CronJobs(namespace).Get(context.TODO(), ownerReference.Name, metav1.GetOptions{})
			if err != nil {
				return retOwner, err
			}
			owner = cronjob.GetOwnerReferences()
		default:
			// Return the current owner if it's not a known type
			retOwner = ownerReference
			return retOwner, nil
		}

		if len(owner) == 0 {
			// Return the current owner if it has no owner
			retOwner = ownerReference
			return retOwner, nil
		}

	}
}
