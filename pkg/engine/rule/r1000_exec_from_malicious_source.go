package rule

import (
	"fmt"
	"strings"

	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

const (
	R1000ExecFromMaliciousSourceRuleName = "R-1000 Exec from malicious source"
)

var R1000ExecFromMaliciousSourceDescriptor = RuleDesciptor{
	Name: R1000ExecFromMaliciousSourceRuleName,
	Tags: []string{"exec", "signature"},
	Requirements: RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.ExecveEventType},
		NeedApplicationProfile: false,
	},
	RuleCreationFunc: func() Rule {
		return CreateRuleR0001ExecWhitelisted()
	},
}

type R1000ExecFromMaliciousSource struct {
}

type R0001ExecFromMaliciousSourceFailure struct {
	RuleName     string
	Err          string
	FailureEvent *tracing.ExecveEvent
}

func (rule *R1000ExecFromMaliciousSource) Name() string {
	return R1000ExecFromMaliciousSourceRuleName
}

func CreateRuleR1000ExecFromMaliciousSource() *R1000ExecFromMaliciousSource {
	return &R1000ExecFromMaliciousSource{}
}

func (rule *R1000ExecFromMaliciousSource) DeleteRule() {
}

func (rule *R1000ExecFromMaliciousSource) ProcessEvent(eventType tracing.EventType, event interface{}, appProfileAccess approfilecache.SingleApplicationProfileAccess) RuleFailure {
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
			return &R0001ExecFromMaliciousSourceFailure{
				RuleName:     rule.Name(),
				Err:          fmt.Sprintf("exec call \"%s\" is from a malicious source \"%s\"", execEvent.PathName, maliciousExecPathPrefix),
				FailureEvent: execEvent,
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

func (rule *R0001ExecFromMaliciousSourceFailure) Name() string {
	return rule.RuleName
}

func (rule *R0001ExecFromMaliciousSourceFailure) Error() string {
	return rule.Err
}

func (rule *R0001ExecFromMaliciousSourceFailure) Event() tracing.GeneralEvent {
	return rule.FailureEvent.GeneralEvent
}
