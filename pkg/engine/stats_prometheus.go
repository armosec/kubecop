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
	ruleCounter           prometheus.Counter
	alertCounter          prometheus.Counter
}

func CreatePrometheusMetric() *prometheusMetric {
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

	//prometheus.MustRegister(perf.RecordReadCounter)
	//prometheus.MustRegister(perf.WaitCounter)

	return &prometheusMetric{
		ebpfExecCounter:       ebpfExecCounter,
		ebpfOpenCounter:       ebpfOpenCounter,
		ebpfNetworkCounter:    ebpfNetworkCounter,
		ebpfDNSCounter:        ebpfDNSCounter,
		ebpfSyscallCounter:    ebpfSyscallCounter,
		ebpfCapabilityCounter: ebpfCapabilityCounter,
		ruleCounter:           ruleCounter,
		alertCounter:          alertCounter,
	}
}

func (p *prometheusMetric) Destroy() {
	prometheus.Unregister(p.ebpfExecCounter)
	prometheus.Unregister(p.ebpfOpenCounter)
	prometheus.Unregister(p.ebpfNetworkCounter)
	prometheus.Unregister(p.ebpfDNSCounter)
	prometheus.Unregister(p.ebpfSyscallCounter)
	prometheus.Unregister(p.ebpfCapabilityCounter)
	prometheus.Unregister(p.ruleCounter)
	prometheus.Unregister(p.alertCounter)
}

func (p *prometheusMetric) ReportEbpfEvent(eventType tracing.EventType) {
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
	}
}

func (p *prometheusMetric) ReportRuleProcessed(ruleID string) {
	p.ruleCounter.Inc()
}

func (p *prometheusMetric) ReportRuleAlereted(ruleID string) {
	p.alertCounter.Inc()
}
