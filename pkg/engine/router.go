package engine

import "github.com/kubescape/kapprofiler/pkg/tracing"

// implemeent EventSink interface for the engine

func (engine *Engine) SendExecveEvent(event *tracing.ExecveEvent) {

}

func (engine *Engine) SendOpenEvent(event *tracing.OpenEvent) {

}

func (engine *Engine) SendNetworkEvent(event *tracing.NetworkEvent) {

}

func (engine *Engine) SendCapabilitiesEvent(event *tracing.CapabilitiesEvent) {

}

func (engine *Engine) SendDnsEvent(event *tracing.DnsEvent) {
}
