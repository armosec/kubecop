package rule

import (
	"fmt"

	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

const (
	R1001ID                               = "R1001"
	R1001ExecBinaryNotInBaseImageRuleName = "Exec Binary Not In Base Image"
)

var R1001ExecBinaryNotInBaseImageRuleDescriptor = RuleDesciptor{
	ID:          R1001ID,
	Name:        R1001ExecBinaryNotInBaseImageRuleName,
	Description: "Detecting exec calls of binaries that are not included in the base image",
	Tags:        []string{"exec", "malicious", "binary", "base image"},
	Priority:    RulePriorityCritical,
	Requirements: RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.ExecveEventType},
		NeedApplicationProfile: false,
	},
	RuleCreationFunc: func() Rule {
		return CreateRuleR1001ExecBinaryNotInBaseImage()
	},
}

type R1001ExecBinaryNotInBaseImage struct {
	BaseRule
}

type R1001ExecBinaryNotInBaseImageFailure struct {
	RuleName         string
	Err              string
	FixSuggestionMsg string
	RulePriority     int
	FailureEvent     *tracing.ExecveEvent
}

func (rule *R1001ExecBinaryNotInBaseImage) Name() string {
	return R1001ExecBinaryNotInBaseImageRuleName
}

func CreateRuleR1001ExecBinaryNotInBaseImage() *R1001ExecBinaryNotInBaseImage {
	return &R1001ExecBinaryNotInBaseImage{}
}

func (rule *R1001ExecBinaryNotInBaseImage) DeleteRule() {
}

func (rule *R1001ExecBinaryNotInBaseImage) ProcessEvent(eventType tracing.EventType, event interface{}, appProfileAccess approfilecache.SingleApplicationProfileAccess, engineAccess EngineAccess) RuleFailure {
	if eventType != tracing.ExecveEventType {
		return nil
	}

	execEvent, ok := event.(*tracing.ExecveEvent)
	if !ok {
		return nil
	}

	if !execEvent.UpperLayer {
		return nil
	}

	return &R1001ExecBinaryNotInBaseImageFailure{
		RuleName:         rule.Name(),
		Err:              fmt.Sprintf("Process image \"%s\" binary is not from the container image \"%s\"", execEvent.PathName, "<image name TBA> via PodSpec"),
		FixSuggestionMsg: "If this is an expected behavior it is strongly suggested to include all executables in the container image. If this is not possible you can remove the rule binding to this workload.",
		FailureEvent:     execEvent,
		RulePriority:     R1001ExecBinaryNotInBaseImageRuleDescriptor.Priority,
	}
}

func (rule *R1001ExecBinaryNotInBaseImage) Requirements() RuleRequirements {
	return RuleRequirements{
		EventTypes:             R1001ExecBinaryNotInBaseImageRuleDescriptor.Requirements.EventTypes,
		NeedApplicationProfile: false,
	}
}

func (rule *R1001ExecBinaryNotInBaseImageFailure) Name() string {
	return rule.RuleName
}

func (rule *R1001ExecBinaryNotInBaseImageFailure) Error() string {
	return rule.Err
}

func (rule *R1001ExecBinaryNotInBaseImageFailure) Event() tracing.GeneralEvent {
	return rule.FailureEvent.GeneralEvent
}

func (rule *R1001ExecBinaryNotInBaseImageFailure) Priority() int {
	return rule.RulePriority
}

func (rule *R1001ExecBinaryNotInBaseImageFailure) FixSuggestion() string {
	return rule.FixSuggestionMsg
}
