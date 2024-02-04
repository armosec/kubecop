package engine

import (
	log "github.com/sirupsen/logrus"

	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/armosec/kubecop/pkg/exporters"
	"github.com/armosec/kubecop/pkg/rulebindingstore"
	"github.com/gammazero/workerpool"
	"github.com/kubescape/kapprofiler/pkg/tracing"
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
	tracer                  *tracing.Tracer
	exporter                exporters.Exporter
	// Event processing worker pool
	eventProcessingPool   *workerpool.WorkerPool
	k8sClientset          ClientSetInterface
	pollLoopRunning       bool
	pollLoopCancelChannel chan struct{}
	promCollector         *prometheusMetric
	getRulesForPodFunc    func(podName, namespace string) ([]rulebindingstore.RuntimeAlertRuleBindingRule, error)
	nodeName              string
}

func NewEngine(k8sClientset ClientSetInterface,
	appProfileCache approfilecache.ApplicationProfileCache,
	tracer *tracing.Tracer,
	exporter exporters.Exporter,
	workerPoolWidth int, nodeName string) *Engine {
	workerPool := workerpool.New(workerPoolWidth)
	engine := Engine{
		applicationProfileCache: appProfileCache,
		k8sClientset:            k8sClientset,
		eventProcessingPool:     workerPool,
		tracer:                  tracer,
		exporter:                exporter,
		promCollector:           createPrometheusMetric(),
		nodeName:                nodeName,
	}
	log.Print("Engine created")
	engine.StartPullComponent()
	return &engine
}

func (e *Engine) SetGetRulesForPodFunc(getRulesForPodFunc func(podName, namespace string) ([]rulebindingstore.RuntimeAlertRuleBindingRule, error)) {
	e.getRulesForPodFunc = getRulesForPodFunc
}

func (e *Engine) Delete() {
	e.StopPullComponent()
	e.eventProcessingPool.StopWait()
	e.promCollector.destroy()
}
