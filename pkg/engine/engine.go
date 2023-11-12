package engine

import (
	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/gammazero/workerpool"
	discovery "k8s.io/client-go/discovery"
	appsv1 "k8s.io/client-go/kubernetes/typed/apps/v1"
	batchv1 "k8s.io/client-go/kubernetes/typed/batch/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

type ClientSetInterface interface {
	CoreV1() corev1.CoreV1Interface
	Discovery() discovery.DiscoveryInterface
	AppsV1() appsv1.AppsV1Interface
	BatchV1() batchv1.BatchV1Interface
}

type Engine struct {
	applicationProfileCache approfilecache.ApplicationProfileCache
	// Event processing worker pool
	eventProcessingPool *workerpool.WorkerPool
	k8sClientset        ClientSetInterface
}

func NewEngine(k8sClientset ClientSetInterface, appProfileCache approfilecache.ApplicationProfileCache, workerPoolWidth int) *Engine {
	workerPool := workerpool.New(workerPoolWidth)
	return &Engine{
		applicationProfileCache: appProfileCache,
		k8sClientset:            k8sClientset,
		eventProcessingPool:     workerPool,
	}
}

func (e *Engine) Delete() {
	e.eventProcessingPool.StopWait()
}
