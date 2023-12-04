package rule

import (
	"slices"

	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

// Current rule:
// Detecting Crypto Miners by looking for outgoing TCP connections to commonly used crypto miners ports.
// TODO: Add more crypto miners ports + add more crypto miners detection methods (e.g. by looking for specific processes and domains).

const (
	R1007ID                   = "R1007"
	R1007CryptoMinersRuleName = "Crypto Miners port detected"
)

var CommonlyUsedCryptoMinersPorts = []uint16{
	3333, // Monero (XMR) - Stratum mining protocol (TCP).
}

var R1007CryptoMinersRuleDescriptor = RuleDesciptor{
	ID:          R1007ID,
	Name:        R1007CryptoMinersRuleName,
	Description: "Detecting Crypto Miners by port.",
	Tags:        []string{"network", "crypto", "miners", "malicious"},
	Priority:    RulePriorityHigh,
	Requirements: RuleRequirements{
		EventTypes: []tracing.EventType{
			tracing.NetworkEventType,
		},
		NeedApplicationProfile: false,
	},
	RuleCreationFunc: func() Rule {
		return CreateRuleR1007CryptoMiners()
	},
}

type R1007CryptoMiners struct {
	BaseRule
}

type R1007CryptoMinersFailure struct {
	RuleName         string
	RulePriority     int
	Err              string
	FixSuggestionMsg string
	FailureEvent     *tracing.NetworkEvent
}

func (rule *R1007CryptoMiners) Name() string {
	return R1007CryptoMinersRuleName
}

func CreateRuleR1007CryptoMiners() *R1007CryptoMiners {
	return &R1007CryptoMiners{}
}

func (rule *R1007CryptoMiners) DeleteRule() {
}

func (rule *R1007CryptoMiners) ProcessEvent(eventType tracing.EventType, event interface{}, appProfileAccess approfilecache.SingleApplicationProfileAccess, engineAccess EngineAccess) RuleFailure {
	if eventType != tracing.NetworkEventType {
		return nil
	}

	networkEvent, ok := event.(*tracing.NetworkEvent)
	if !ok {
		return nil
	}

	if networkEvent.Protocol == "TCP" && networkEvent.PacketType == "OUTGOING" && slices.Contains(CommonlyUsedCryptoMinersPorts, networkEvent.Port) {
		return &R1007CryptoMinersFailure{
			RuleName:         rule.Name(),
			Err:              "Possible Crypto Miner port detected",
			FailureEvent:     networkEvent,
			FixSuggestionMsg: "If this is a legitimate action, please consider removing this workload from the binding of this rule.",
			RulePriority:     R1007CryptoMinersRuleDescriptor.Priority,
		}
	}

	return nil
}

func (rule *R1007CryptoMiners) Requirements() RuleRequirements {
	return RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.NetworkEventType},
		NeedApplicationProfile: false,
	}
}

func (rule *R1007CryptoMinersFailure) Name() string {
	return rule.RuleName
}

func (rule *R1007CryptoMinersFailure) Error() string {
	return rule.Err
}

func (rule *R1007CryptoMinersFailure) Event() tracing.GeneralEvent {
	return rule.FailureEvent.GeneralEvent
}

func (rule *R1007CryptoMinersFailure) Priority() int {
	return rule.RulePriority
}

func (rule *R1007CryptoMinersFailure) FixSuggestion() string {
	return rule.FixSuggestionMsg
}
