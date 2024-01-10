package rule

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

const (
	R0006ID                                          = "R0006"
	R0006UnexpectedServiceAccountTokenAccessRuleName = "Unexpected Service Account Token Access"
)

// ServiceAccountTokenPathsPrefixs is a list because of symlinks.
var ServiceAccountTokenPathsPrefixs = []string{
	"/run/secrets/kubernetes.io/serviceaccount",
	"/var/run/secrets/kubernetes.io/serviceaccount",
}

var R0006UnexpectedServiceAccountTokenAccessRuleDescriptor = RuleDesciptor{
	ID:          R0006ID,
	Name:        R0006UnexpectedServiceAccountTokenAccessRuleName,
	Description: "Detecting unexpected access to service account token.",
	Tags:        []string{"token", "malicious", "whitelisted"},
	Priority:    RulePriorityHigh,
	Requirements: RuleRequirements{
		EventTypes: []tracing.EventType{
			tracing.OpenEventType,
		},
		NeedApplicationProfile: true,
	},
	RuleCreationFunc: func() Rule {
		return CreateRuleR0006UnexpectedServiceAccountTokenAccess()
	},
}

type R0006UnexpectedServiceAccountTokenAccess struct {
	BaseRule
}

type R0006UnexpectedServiceAccountTokenAccessFailure struct {
	RuleName         string
	RulePriority     int
	Err              string
	FixSuggestionMsg string
	FailureEvent     *tracing.OpenEvent
}

func (rule *R0006UnexpectedServiceAccountTokenAccess) Name() string {
	return R0006UnexpectedServiceAccountTokenAccessRuleName
}

func CreateRuleR0006UnexpectedServiceAccountTokenAccess() *R0006UnexpectedServiceAccountTokenAccess {
	return &R0006UnexpectedServiceAccountTokenAccess{}
}

func (rule *R0006UnexpectedServiceAccountTokenAccess) DeleteRule() {
}

func (rule *R0006UnexpectedServiceAccountTokenAccess) generatePatchCommand(event *tracing.OpenEvent, appProfileAccess approfilecache.SingleApplicationProfileAccess) string {
	flagList := "["
	for _, arg := range event.Flags {
		flagList += "\"" + arg + "\","
	}
	// remove the last comma
	if len(flagList) > 1 {
		flagList = flagList[:len(flagList)-1]
	}
	baseTemplate := "kubectl patch applicationprofile %s --namespace %s --type merge -p '{\"spec\": {\"containers\": [{\"name\": \"%s\", \"opens\": [{\"path\": \"%s\", \"flags\": %s}]}]}}'"
	return fmt.Sprintf(baseTemplate, appProfileAccess.GetName(), appProfileAccess.GetNamespace(),
		event.ContainerName, event.PathName, flagList)
}

func (rule *R0006UnexpectedServiceAccountTokenAccess) ProcessEvent(eventType tracing.EventType, event interface{}, appProfileAccess approfilecache.SingleApplicationProfileAccess, engineAccess EngineAccess) RuleFailure {
	if eventType != tracing.OpenEventType {
		return nil
	}

	openEvent, ok := event.(*tracing.OpenEvent)
	if !ok {
		return nil
	}

	shouldCheckEvent := false

	for _, prefix := range ServiceAccountTokenPathsPrefixs {
		if strings.HasPrefix(openEvent.PathName, prefix) {
			shouldCheckEvent = true
			break
		}
	}

	if !shouldCheckEvent {
		log.Debugf("Skipping event %s because it is not a service account token\n", openEvent.PathName)
		return nil
	}

	if appProfileAccess == nil {
		return &R0006UnexpectedServiceAccountTokenAccessFailure{
			RuleName:         rule.Name(),
			Err:              "Application profile is missing",
			FixSuggestionMsg: fmt.Sprintf("Please create an application profile for the Pod %s", openEvent.PodName),
			FailureEvent:     openEvent,
			RulePriority:     R0006UnexpectedServiceAccountTokenAccessRuleDescriptor.Priority,
		}
	}

	appProfileOpenList, err := appProfileAccess.GetOpenList()
	if err != nil || appProfileOpenList == nil {
		return &R0006UnexpectedServiceAccountTokenAccessFailure{
			RuleName:         rule.Name(),
			Err:              "Application profile is missing",
			FixSuggestionMsg: fmt.Sprintf("Please create an application profile for the Pod %s", openEvent.PodName),
			FailureEvent:     openEvent,
			RulePriority:     R0006UnexpectedServiceAccountTokenAccessRuleDescriptor.Priority,
		}
	}

	for _, open := range *appProfileOpenList {
		for _, prefix := range ServiceAccountTokenPathsPrefixs {
			if strings.HasPrefix(open.Path, prefix) {
				return nil
			}
		}
	}

	return &R0006UnexpectedServiceAccountTokenAccessFailure{
		RuleName:         rule.Name(),
		Err:              fmt.Sprintf("Unexpected access to service account token: %s", openEvent.PathName),
		FixSuggestionMsg: fmt.Sprintf("If this is a valid behavior, please add the open call \"%s\" to the whitelist in the application profile for the Pod \"%s\". You can use the following command: %s", openEvent.PathName, openEvent.PodName, rule.generatePatchCommand(openEvent, appProfileAccess)),
		FailureEvent:     openEvent,
		RulePriority:     R0006UnexpectedServiceAccountTokenAccessRuleDescriptor.Priority,
	}
}

func (rule *R0006UnexpectedServiceAccountTokenAccess) Requirements() RuleRequirements {
	return RuleRequirements{
		EventTypes:             []tracing.EventType{tracing.OpenEventType},
		NeedApplicationProfile: true,
	}
}

func (rule *R0006UnexpectedServiceAccountTokenAccessFailure) Name() string {
	return rule.RuleName
}

func (rule *R0006UnexpectedServiceAccountTokenAccessFailure) Error() string {
	return rule.Err
}

func (rule *R0006UnexpectedServiceAccountTokenAccessFailure) Event() tracing.GeneralEvent {
	return rule.FailureEvent.GeneralEvent
}

func (rule *R0006UnexpectedServiceAccountTokenAccessFailure) Priority() int {
	return rule.RulePriority
}

func (rule *R0006UnexpectedServiceAccountTokenAccessFailure) FixSuggestion() string {
	return rule.FixSuggestionMsg
}
