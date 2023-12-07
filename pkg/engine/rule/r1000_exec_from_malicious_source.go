package rule

import (
	"fmt"
	"strings"

	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

const (
	R1000ID                              = "R1000"
	R1000ExecFromMaliciousSourceRuleName = "Exec from malicious source"
)

var R1000ExecFromMaliciousSourceDescriptor = RuleDesciptor{
	ID:          R1000ID,
	Name:        R1000ExecFromMaliciousSourceRuleName,
	Description: "Detecting exec calls that are from malicious source like: /dev/shm, /run, /var/run, /proc/self",
	Priority:    RulePriorityCritical,
	Tags:        []string{"exec", "signature"},
	Requirements: RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.ExecveEventType},
		NeedApplicationProfile: false,
	},
	RuleCreationFunc: func() Rule {
		return CreateRuleR1000ExecFromMaliciousSource()
	},
}

type R1000ExecFromMaliciousSource struct {
	BaseRule
}

type R1000ExecFromMaliciousSourceFailure struct {
	RuleName         string
	RulePriority     int
	FixSuggestionMsg string
	Err              string
	FailureEvent     *tracing.ExecveEvent
}

func (rule *R1000ExecFromMaliciousSource) Name() string {
	return R1000ExecFromMaliciousSourceRuleName
}

func CreateRuleR1000ExecFromMaliciousSource() *R1000ExecFromMaliciousSource {
	return &R1000ExecFromMaliciousSource{}
}

func (rule *R1000ExecFromMaliciousSource) DeleteRule() {
}

func (rule *R1000ExecFromMaliciousSource) ProcessEvent(eventType tracing.EventType, event interface{}, appProfileAccess approfilecache.SingleApplicationProfileAccess, engineAccess EngineAccess) RuleFailure {
	if eventType != tracing.ExecveEventType {
		return nil
	}

	execEvent, ok := event.(*tracing.ExecveEvent)
	if !ok {
		return nil
	}

	var maliciousExecPathPrefixes = []string{
		"/dev/shm",
		"/run",
		"/var/run",
		"/proc/self",
	}

	// /proc/self/fd/<n> is classic way to hide malicious execs
	// (see ezuri packer for example)
	// Here it would be even more interesting to check if the fd
	// is memory mapped file

	// The assumption here is that the event path is absolute!

	for _, maliciousExecPathPrefix := range maliciousExecPathPrefixes {
		if strings.HasPrefix(execEvent.PathName, maliciousExecPathPrefix) {
			return &R1000ExecFromMaliciousSourceFailure{
				RuleName:         rule.Name(),
				Err:              fmt.Sprintf("exec call \"%s\" is from a malicious source \"%s\"", execEvent.PathName, maliciousExecPathPrefix),
				FixSuggestionMsg: "If this is a legitimate action, please add consider removing this workload from the binding of this rule.",
				FailureEvent:     execEvent,
				RulePriority:     R1000ExecFromMaliciousSourceDescriptor.Priority,
			}
		}
	}

	return nil
}

func (rule *R1000ExecFromMaliciousSource) Requirements() RuleRequirements {
	return RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.ExecveEventType},
		NeedApplicationProfile: false,
	}
}

func (rule *R1000ExecFromMaliciousSourceFailure) Name() string {
	return rule.RuleName
}

func (rule *R1000ExecFromMaliciousSourceFailure) Error() string {
	return rule.Err
}

func (rule *R1000ExecFromMaliciousSourceFailure) Event() tracing.GeneralEvent {
	return rule.FailureEvent.GeneralEvent
}

func (rule *R1000ExecFromMaliciousSourceFailure) Priority() int {
	return rule.RulePriority
}

func (rule *R1000ExecFromMaliciousSourceFailure) FixSuggestion() string {
	return rule.FixSuggestionMsg
}
