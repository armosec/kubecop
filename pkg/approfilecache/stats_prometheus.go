package approfilecache

import (
	"github.com/prometheus/client_golang/prometheus"
)

type prometheusMetric struct {
	createCounter prometheus.Counter
	updateCounter prometheus.Counter
	deleteCounter prometheus.Counter
}

func createPrometheusMetric() *prometheusMetric {
	createCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kubecop_application_profile_create_counter",
		Help: "The total number of application profile creations",
	})
	prometheus.MustRegister(createCounter)

	updateCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kubecop_application_profile_update_counter",
		Help: "The total number of application profile updates",
	})
	prometheus.MustRegister(updateCounter)

	deleteCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kubecop_application_profile_delete_counter",
		Help: "The total number of application profile deletions",
	})
	prometheus.MustRegister(deleteCounter)

	return &prometheusMetric{
		createCounter: createCounter,
		updateCounter: updateCounter,
		deleteCounter: deleteCounter,
	}
}

func (p *prometheusMetric) destroy() {
	prometheus.Unregister(p.createCounter)
	prometheus.Unregister(p.updateCounter)
	prometheus.Unregister(p.deleteCounter)
}

func (p *prometheusMetric) reportApplicationProfileCreated() {
	p.createCounter.Inc()
}

func (p *prometheusMetric) reportApplicationProfileUpdated() {
	p.updateCounter.Inc()
}

func (p *prometheusMetric) reportApplicationProfileDeleted() {
	p.deleteCounter.Inc()
}
