package rule

import (
	"slices"

	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

// Current rule:
// Detecting Crypto Miners by looking for outgoing TCP connections to commonly used crypto miners ports and common pools dns names.
// TODO: Add more crypto miners ports + add more crypto miners detection methods (e.g. by looking for specific processes and domains).
// Find a reliable way to detect crypto miners.

const (
	R1007ID                   = "R1007"
	R1007CryptoMinersRuleName = "Crypto Miner detected"
)

var CommonlyUsedCryptoMinersPorts = []uint16{
	3333,  // Monero (XMR) - Stratum mining protocol (TCP).
	45700, // Monero (XMR) - Stratum mining protocol (TCP). (stratum+tcp://xmr.pool.minergate.com)
}

var CommonlyUsedCryptoMinersDomains = []string{
	"2cryptocalc.com",
	"2miners.com",
	"antpool.com",
	"asia1.ethpool.org",
	"bohemianpool.com",
	"botbox.dev",
	"btm.antpool.com",
	"c3pool.com",
	"c4pool.org",
	"ca.minexmr.com",
	"cn.stratum.slushpool.com",
	"dash.antpool.com",
	"data.miningpoolstats.stream",
	"de.minexmr.com",
	"eth-ar.dwarfpool.com",
	"eth-asia.dwarfpool.com",
	"eth-asia1.nanopool.org",
	"eth-au.dwarfpool.com",
	"eth-au1.nanopool.org",
	"eth-br.dwarfpool.com",
	"eth-cn.dwarfpool.com",
	"eth-cn2.dwarfpool.com",
	"eth-eu.dwarfpool.com",
	"eth-eu1.nanopool.org",
	"eth-eu2.nanopool.org",
	"eth-hk.dwarfpool.com",
	"eth-jp1.nanopool.org",
	"eth-ru.dwarfpool.com",
	"eth-ru2.dwarfpool.com",
	"eth-sg.dwarfpool.com",
	"eth-us-east1.nanopool.org",
	"eth-us-west1.nanopool.org",
	"eth-us.dwarfpool.com",
	"eth-us2.dwarfpool.com",
	"eth.antpool.com",
	"eu.stratum.slushpool.com",
	"eu1.ethermine.org",
	"eu1.ethpool.org",
	"fastpool.xyz",
	"fr.minexmr.com",
	"kriptokyng.com",
	"mine.moneropool.com",
	"mine.xmrpool.net",
	"miningmadness.com",
	"monero.cedric-crispin.com",
	"monero.crypto-pool.fr",
	"monero.fairhash.org",
	"monero.hashvault.pro",
	"monero.herominers.com",
	"monerod.org",
	"monerohash.com",
	"moneroocean.stream",
	"monerop.com",
	"multi-pools.com",
	"p2pool.io",
	"pool.kryptex.com",
	"pool.minexmr.com",
	"pool.monero.hashvault.pro",
	"pool.rplant.xyz",
	"pool.supportxmr.com",
	"pool.xmr.pt",
	"prohashing.com",
	"rx.unmineable.com",
	"sg.minexmr.com",
	"sg.stratum.slushpool.com",
	"skypool.org",
	"solo-xmr.2miners.com",
	"ss.antpool.com",
	"stratum-btm.antpool.com",
	"stratum-dash.antpool.com",
	"stratum-eth.antpool.com",
	"stratum-ltc.antpool.com",
	"stratum-xmc.antpool.com",
	"stratum-zec.antpool.com",
	"stratum.antpool.com",
	"supportxmr.com",
	"trustpool.cc",
	"us-east.stratum.slushpool.com",
	"us1.ethermine.org",
	"us1.ethpool.org",
	"us2.ethermine.org",
	"us2.ethpool.org",
	"web.xmrpool.eu",
	"www.domajorpool.com",
	"www.dxpool.com",
	"www.mining-dutch.nl",
	"xmc.antpool.com",
	"xmr-asia1.nanopool.org",
	"xmr-au1.nanopool.org",
	"xmr-eu1.nanopool.org",
	"xmr-eu2.nanopool.org",
	"xmr-jp1.nanopool.org",
	"xmr-us-east1.nanopool.org",
	"xmr-us-west1.nanopool.org",
	"xmr.2miners.com",
	"xmr.crypto-pool.fr",
	"xmr.gntl.uk",
	"xmr.nanopool.org",
	"xmr.pool-pay.com",
	"xmr.pool.minergate.com",
	"xmr.solopool.org",
	"xmr.volt-mine.com",
	"xmr.zeropool.io",
	"zec.antpool.com",
	"zergpool.com",
}

var R1007CryptoMinersRuleDescriptor = RuleDesciptor{
	ID:          R1007ID,
	Name:        R1007CryptoMinersRuleName,
	Description: "Detecting Crypto Miners by port, domain and randomx event.",
	Tags:        []string{"network", "crypto", "miners", "malicious", "dns"},
	Priority:    RulePriorityHigh,
	Requirements: RuleRequirements{
		EventTypes: []tracing.EventType{
			tracing.NetworkEventType,
			tracing.DnsEventType,
			tracing.RandomXEventType,
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
	FailureEvent     *tracing.GeneralEvent
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
	if eventType != tracing.NetworkEventType && eventType != tracing.DnsEventType && eventType != tracing.RandomXEventType {
		return nil
	}

	if randomXEvent, ok := event.(*tracing.RandomXEvent); ok {
		return &R1007CryptoMinersFailure{
			RuleName:         rule.Name(),
			Err:              "Possible Crypto Miner detected",
			FailureEvent:     &randomXEvent.GeneralEvent,
			FixSuggestionMsg: "If this is a legitimate action, please consider removing this workload from the binding of this rule.",
			RulePriority:     R1007CryptoMinersRuleDescriptor.Priority,
		}
	} else if networkEvent, ok := event.(*tracing.NetworkEvent); ok {
		if networkEvent.Protocol == "TCP" && networkEvent.PacketType == "OUTGOING" && slices.Contains(CommonlyUsedCryptoMinersPorts, networkEvent.Port) {
			return &R1007CryptoMinersFailure{
				RuleName:         rule.Name(),
				Err:              "Possible Crypto Miner port detected",
				FailureEvent:     &networkEvent.GeneralEvent,
				FixSuggestionMsg: "If this is a legitimate action, please consider removing this workload from the binding of this rule.",
				RulePriority:     R1007CryptoMinersRuleDescriptor.Priority,
			}
		}
	} else if dnsEvent, ok := event.(*tracing.DnsEvent); ok {
		if slices.Contains(CommonlyUsedCryptoMinersDomains, dnsEvent.DnsName) {
			return &R1007CryptoMinersFailure{
				RuleName:         rule.Name(),
				Err:              "Possible Crypto Miner domain detected",
				FailureEvent:     &dnsEvent.GeneralEvent,
				FixSuggestionMsg: "If this is a legitimate action, please consider removing this workload from the binding of this rule.",
				RulePriority:     R1007CryptoMinersRuleDescriptor.Priority,
			}
		}
	}

	return nil
}

func (rule *R1007CryptoMiners) Requirements() RuleRequirements {
	return RuleRequirements{
		EventTypes:             R1007CryptoMinersRuleDescriptor.Requirements.EventTypes,
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
	return *rule.FailureEvent
}

func (rule *R1007CryptoMinersFailure) Priority() int {
	return rule.RulePriority
}

func (rule *R1007CryptoMinersFailure) FixSuggestion() string {
	return rule.FixSuggestionMsg
}
