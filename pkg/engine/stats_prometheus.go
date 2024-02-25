package engine

import (
	"github.com/kubescape/kapprofiler/pkg/tracing"
	"github.com/prometheus/client_golang/prometheus"
)

type prometheusMetric struct {
	ebpfExecCounter       prometheus.Counter
	ebpfOpenCounter       prometheus.Counter
	ebpfNetworkCounter    prometheus.Counter
	ebpfDNSCounter        prometheus.Counter
	ebpfSyscallCounter    prometheus.Counter
	ebpfCapabilityCounter prometheus.Counter
	ebpfRandomXCounter    prometheus.Counter
	ebpfFailedCounter     prometheus.Counter
	ruleCounter           prometheus.Counter
	alertCounter          prometheus.Counter
}

func createPrometheusMetric() *prometheusMetric {
	ebpfExecCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kubecop_exec_counter",
		Help: "The total number of exec events received from the eBPF probe",
	})
	prometheus.MustRegister(ebpfExecCounter)

	ebpfOpenCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kubecop_open_counter",
		Help: "The total number of open events received from the eBPF probe",
	})
	prometheus.MustRegister(ebpfOpenCounter)

	ebpfNetworkCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kubecop_network_counter",
		Help: "The total number of network events received from the eBPF probe",
	})
	prometheus.MustRegister(ebpfNetworkCounter)

	ebpfDNSCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kubecop_dns_counter",
		Help: "The total number of DNS events received from the eBPF probe",
	})
	prometheus.MustRegister(ebpfDNSCounter)

	ebpfSyscallCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kubecop_syscall_counter",
		Help: "The total number of syscall events received from the eBPF probe",
	})
	prometheus.MustRegister(ebpfSyscallCounter)

	ebpfCapabilityCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kubecop_capability_counter",
		Help: "The total number of capability events received from the eBPF probe",
	})
	prometheus.MustRegister(ebpfCapabilityCounter)

	ebpfRandomXCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kubecop_randomx_counter",
		Help: "The total number of randomx events received from the eBPF probe",
	})
	prometheus.MustRegister(ebpfRandomXCounter)

	ruleCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kubecop_rule_counter",
		Help: "The total number of rules processed by the engine",
	})
	prometheus.MustRegister(ruleCounter)

	alertCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kubecop_alert_counter",
		Help: "The total number of alerts sent by the engine",
	})
	prometheus.MustRegister(alertCounter)

	ebpfFailedCounter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kubecop_ebpf_event_failure_counter",
		Help: "The total number of failed events received from the eBPF probe",
	})
	prometheus.MustRegister(ebpfFailedCounter)

	return &prometheusMetric{
		ebpfExecCounter:       ebpfExecCounter,
		ebpfOpenCounter:       ebpfOpenCounter,
		ebpfNetworkCounter:    ebpfNetworkCounter,
		ebpfDNSCounter:        ebpfDNSCounter,
		ebpfSyscallCounter:    ebpfSyscallCounter,
		ebpfCapabilityCounter: ebpfCapabilityCounter,
		ebpfRandomXCounter:    ebpfRandomXCounter,
		ebpfFailedCounter:     ebpfFailedCounter,
		ruleCounter:           ruleCounter,
		alertCounter:          alertCounter,
	}
}

func (p *prometheusMetric) destroy() {
	prometheus.Unregister(p.ebpfExecCounter)
	prometheus.Unregister(p.ebpfOpenCounter)
	prometheus.Unregister(p.ebpfNetworkCounter)
	prometheus.Unregister(p.ebpfDNSCounter)
	prometheus.Unregister(p.ebpfSyscallCounter)
	prometheus.Unregister(p.ebpfCapabilityCounter)
	prometheus.Unregister(p.ebpfRandomXCounter)
	prometheus.Unregister(p.ebpfFailedCounter)
	prometheus.Unregister(p.ruleCounter)
	prometheus.Unregister(p.alertCounter)
}

func (p *prometheusMetric) reportEbpfEvent(eventType tracing.EventType) {
	switch eventType {
	case tracing.ExecveEventType:
		p.ebpfExecCounter.Inc()
	case tracing.OpenEventType:
		p.ebpfOpenCounter.Inc()
	case tracing.NetworkEventType:
		p.ebpfNetworkCounter.Inc()
	case tracing.DnsEventType:
		p.ebpfDNSCounter.Inc()
	case tracing.SyscallEventType:
		p.ebpfSyscallCounter.Inc()
	case tracing.CapabilitiesEventType:
		p.ebpfCapabilityCounter.Inc()
	case tracing.RandomXEventType:
		p.ebpfRandomXCounter.Inc()
	}
}

func (p *prometheusMetric) reportEbpfFailedEvent() {
	p.ebpfFailedCounter.Inc()
}

func (p *prometheusMetric) reportRuleProcessed(ruleID string) {
	p.ruleCounter.Inc()
}

func (p *prometheusMetric) reportRuleAlereted(ruleID string) {
	p.alertCounter.Inc()
}
