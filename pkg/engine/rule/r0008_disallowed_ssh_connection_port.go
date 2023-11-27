package rule

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

const (
	R0008ID                                  = "R0008"
	R0008DisallowedSSHConnectionPortRuleName = "Disallowed SSH Connection Port"
	MaxTimeDiffInSeconds                     = 3
)

var SSHRelatedFiles = []string{
	"ssh_config",
	"sshd_config",
	"ssh_known_hosts",
	"ssh_known_hosts2",
	"ssh_config.d",
	"sshd_config.d",
	".ssh",
	"authorized_keys",
	"authorized_keys2",
	"known_hosts",
	"known_hosts2",
	"id_rsa",
	"id_rsa.pub",
	"id_dsa",
	"id_dsa.pub",
	"id_ecdsa",
	"id_ecdsa.pub",
	"id_ed25519",
	"id_ed25519.pub",
	"id_xmss",
	"id_xmss.pub",
}

var R0008DisallowedSSHConnectionPortRuleDescriptor = RuleDesciptor{
	ID:          R0008ID,
	Name:        R0008DisallowedSSHConnectionPortRuleName,
	Description: "Detecting ssh connection to disallowed port",
	Tags:        []string{"ssh", "connection", "port", "malicious"},
	Priority:    7,
	Requirements: RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.OpenEventType, tracing.NetworkEventType},
		NeedApplicationProfile: false,
	},
	RuleCreationFunc: func() Rule {
		return CreateRuleR0008DisallowedSSHConnectionPort()
	},
}

type R0008DisallowedSSHConnectionPort struct {
	accessRelatedFiles        bool
	sshInitiatorPid           uint32
	configFileAccessTimeStamp int64
}

type R0008DisallowedSSHConnectionPortFailure struct {
	RuleName     string
	Err          string
	RulePriority int
	FailureEvent *tracing.NetworkEvent
}

func (rule *R0008DisallowedSSHConnectionPort) Name() string {
	return R0008DisallowedSSHConnectionPortRuleName
}

func CreateRuleR0008DisallowedSSHConnectionPort() *R0008DisallowedSSHConnectionPort {
	return &R0008DisallowedSSHConnectionPort{accessRelatedFiles: false, sshInitiatorPid: 0, configFileAccessTimeStamp: 0}
}

func (rule *R0008DisallowedSSHConnectionPort) DeleteRule() {
}

func (rule *R0008DisallowedSSHConnectionPort) ProcessEvent(eventType tracing.EventType, event interface{}, appProfileAccess approfilecache.SingleApplicationProfileAccess) RuleFailure {
	if eventType != tracing.OpenEventType && eventType != tracing.NetworkEventType {
		return nil
	}

	if eventType == tracing.OpenEventType && !rule.accessRelatedFiles {
		openEvent, ok := event.(*tracing.OpenEvent)
		if !ok {
			return nil
		} else {
			if IsSSHConfigFile(openEvent.PathName) {
				rule.accessRelatedFiles = true
				rule.sshInitiatorPid = openEvent.Pid
				rule.configFileAccessTimeStamp = openEvent.Timestamp
			}

			return nil
		}
	} else if eventType == tracing.NetworkEventType && rule.accessRelatedFiles {
		networkEvent, ok := event.(*tracing.NetworkEvent)
		if !ok {
			return nil
		}

		timestampDiffInSeconds := calculateTimestampDiffInSeconds(networkEvent.Timestamp, rule.configFileAccessTimeStamp)
		if timestampDiffInSeconds > MaxTimeDiffInSeconds {
			rule.accessRelatedFiles = false
			rule.sshInitiatorPid = 0
			rule.configFileAccessTimeStamp = 0
			return nil
		}
		if networkEvent.Pid == rule.sshInitiatorPid && networkEvent.PacketType == "OUTGOING" && networkEvent.Protocol == "TCP" && networkEvent.Port != 22 {
			rule.accessRelatedFiles = false
			rule.sshInitiatorPid = 0
			rule.configFileAccessTimeStamp = 0
			return &R0008DisallowedSSHConnectionPortFailure{
				RuleName:     rule.Name(),
				Err:          fmt.Sprintf("ssh connection to port %d is not allowed", networkEvent.Port),
				FailureEvent: networkEvent,
				RulePriority: R0008DisallowedSSHConnectionPortRuleDescriptor.Priority,
			}
		}
	}

	return nil
}

func calculateTimestampDiffInSeconds(timestamp1 int64, timestamp2 int64) int64 {
	return (timestamp1 - timestamp2) / int64(time.Second)
}

func IsSSHConfigFile(path string) bool {
	for _, sshFile := range SSHRelatedFiles {
		if strings.Contains(path, sshFile) {
			log.Printf("Found SSH related file: %s\n", path)
			return true
		}
	}
	return false
}

func (rule *R0008DisallowedSSHConnectionPort) Requirements() RuleRequirements {
	return RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.OpenEventType, tracing.NetworkEventType},
		NeedApplicationProfile: false,
	}
}

func (rule *R0008DisallowedSSHConnectionPortFailure) Name() string {
	return rule.RuleName
}

func (rule *R0008DisallowedSSHConnectionPortFailure) Error() string {
	return rule.Err
}

func (rule *R0008DisallowedSSHConnectionPortFailure) Event() tracing.GeneralEvent {
	return rule.FailureEvent.GeneralEvent
}

func (rule *R0008DisallowedSSHConnectionPortFailure) Priority() int {
	return rule.RulePriority
}
