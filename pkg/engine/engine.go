package engine

import (
	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/gammazero/workerpool"
	"k8s.io/client-go/kubernetes"
)

type Engine struct {
	applicationProfileCache approfilecache.ApplicationProfileCache
	// Event processing worker pool
	eventProcessingPool *workerpool.WorkerPool
	shouldStop          bool
	k8sClientset        *kubernetes.Clientset
}

func NewEngine(k8sClientset *kubernetes.Clientset, appProfileCache approfilecache.ApplicationProfileCache, workerPoolWidth int) *Engine {
	workerPool := workerpool.New(workerPoolWidth)
	return &Engine{
		applicationProfileCache: appProfileCache,
		k8sClientset:            k8sClientset,
		eventProcessingPool:     workerPool,
		shouldStop:              false,
	}
}
