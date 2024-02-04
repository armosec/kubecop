package rule

import (
	"fmt"
	"slices"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

const (
	R1003ID                             = "R1003"
	R1003MaliciousSSHConnectionRuleName = "Malicious SSH Connection"
	MaxTimeDiffInSeconds                = 2
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

var R1003MaliciousSSHConnectionRuleDescriptor = RuleDesciptor{
	ID:          R1003ID,
	Name:        R1003MaliciousSSHConnectionRuleName,
	Description: "Detecting ssh connection to disallowed port",
	Tags:        []string{"ssh", "connection", "port", "malicious"},
	Priority:    RulePriorityHigh,
	Requirements: RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.OpenEventType, tracing.NetworkEventType},
		NeedApplicationProfile: false,
	},
	RuleCreationFunc: func() Rule {
		return CreateRuleR1003MaliciousSSHConnection()
	},
}

type R1003MaliciousSSHConnection struct {
	BaseRule
	accessRelatedFiles        bool
	sshInitiatorPid           uint32
	configFileAccessTimeStamp int64
	allowedPorts              []uint16
}

type R1003MaliciousSSHConnectionFailure struct {
	RuleName         string
	Err              string
	FixSuggestionMsg string
	RulePriority     int
	FailureEvent     *tracing.NetworkEvent
}

func (rule *R1003MaliciousSSHConnection) Name() string {
	return R1003MaliciousSSHConnectionRuleName
}

func CreateRuleR1003MaliciousSSHConnection() *R1003MaliciousSSHConnection {
	return &R1003MaliciousSSHConnection{accessRelatedFiles: false,
		sshInitiatorPid:           0,
		configFileAccessTimeStamp: 0,
		allowedPorts:              []uint16{22},
	}
}

func (rule *R1003MaliciousSSHConnection) SetParameters(params map[string]interface{}) {
	if allowedPortsInterface, ok := params["allowedPorts"].([]interface{}); ok {
		if len(allowedPortsInterface) == 0 {
			log.Printf("No allowed ports were provided for rule %s. Defaulting to port 22\n", rule.Name())
			return
		}

		var allowedPorts []uint16
		for _, port := range allowedPortsInterface {
			if convertedPort, ok := port.(float64); ok {
				allowedPorts = append(allowedPorts, uint16(convertedPort))
			} else {
				log.Errorf("Failed to convert port %v to uint16\n", port)
			}
		}

		log.Printf("Set parameters for rule %s. Allowed ports: %v\n", rule.Name(), allowedPorts)
		rule.allowedPorts = allowedPorts
	} else {
		log.Errorf("Failed to set parameters for rule %s. Allowed ports: %v\n", rule.Name(), params["allowedPorts"])
	}
}

func (rule *R1003MaliciousSSHConnection) DeleteRule() {
}

func (rule *R1003MaliciousSSHConnection) ProcessEvent(eventType tracing.EventType, event interface{}, appProfileAccess approfilecache.SingleApplicationProfileAccess, engineAccess EngineAccess) RuleFailure {
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
		if networkEvent.Pid == rule.sshInitiatorPid && networkEvent.PacketType == "OUTGOING" && networkEvent.Protocol == "TCP" && !slices.Contains(rule.allowedPorts, networkEvent.Port) {
			rule.accessRelatedFiles = false
			rule.sshInitiatorPid = 0
			rule.configFileAccessTimeStamp = 0
			return &R1003MaliciousSSHConnectionFailure{
				RuleName:         rule.Name(),
				Err:              fmt.Sprintf("ssh connection to port %d is not allowed", networkEvent.Port),
				FixSuggestionMsg: "If this is a legitimate action, please add the port as a parameter to the binding of this rule",
				FailureEvent:     networkEvent,
				RulePriority:     R1003MaliciousSSHConnectionRuleDescriptor.Priority,
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

func (rule *R1003MaliciousSSHConnection) Requirements() RuleRequirements {
	return RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.OpenEventType, tracing.NetworkEventType},
		NeedApplicationProfile: false,
	}
}

func (rule *R1003MaliciousSSHConnectionFailure) Name() string {
	return rule.RuleName
}

func (rule *R1003MaliciousSSHConnectionFailure) Error() string {
	return rule.Err
}

func (rule *R1003MaliciousSSHConnectionFailure) Event() tracing.GeneralEvent {
	return rule.FailureEvent.GeneralEvent
}

func (rule *R1003MaliciousSSHConnectionFailure) Priority() int {
	return rule.RulePriority
}

func (rule *R1003MaliciousSSHConnectionFailure) FixSuggestion() string {
	return rule.FixSuggestionMsg
}
