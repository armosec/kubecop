package engine

import (
	"context"
	"log"
	"os"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/armosec/kubecop/pkg/engine/rule"
)

func (engine *Engine) Action(ruleFailure rule.RuleFailure, action rule.Action) {
	switch action {
	case rule.KillPodAction:
		engine.KillPod(ruleFailure)
	case rule.KillProcessAction:
		engine.KillProcess(ruleFailure)
	case rule.NoAction:
		if os.Getenv("DEBUG") == "true" {
			log.Printf("Skipping action for rule %s", ruleFailure.Name())
		}
	default:
		log.Printf("Unknown action %s for rule %s", action, ruleFailure.Name())
	}

}

// KillPod kills the pod that caused the rule failure.
// TODO: Add a check if the pod is part of a deployment or a statefulset.
func (engine *Engine) KillPod(ruleFailure rule.RuleFailure) {
	log.Printf("Killing pod %s in namespace %s", ruleFailure.Event().PodName, ruleFailure.Event().Namespace)
	err := engine.k8sClientset.CoreV1().Pods(ruleFailure.Event().Namespace).Delete(context.TODO(), ruleFailure.Event().PodName, metav1.DeleteOptions{})
	if err != nil {
		log.Printf("Failed to delete pod %s in namespace %s: %v", ruleFailure.Event().PodName, ruleFailure.Event().Namespace, err)
	}
}

// KillProcess kills the process that caused the rule failure - hostPID must be enabled.
// Killing the process might cause a crash loop, so it's not recommended.
func (engine *Engine) KillProcess(ruleFailure rule.RuleFailure) {
	log.Printf("Killing process %d in namespace %s", ruleFailure.Event().Pid, ruleFailure.Event().Namespace)
	proc, err := os.FindProcess(int(ruleFailure.Event().Pid))
	if err != nil {
		log.Printf("Failed to find process %d: %v", ruleFailure.Event().Pid, err)
		return
	}

	err = proc.Kill()
	if err != nil {
		log.Printf("Failed to kill process %d: %v", ruleFailure.Event().Pid, err)
		return
	}

}
