
import sys
import re

rule_id = sys.argv[1]

# Verify rule id looks like {rule_id}
if not re.match(r'R[0-9]{4}', rule_id):
    print('Rule id must be in the format {rule_id}')
    sys.exit(1)

rule_name = ' '.join(sys.argv[2:])
rule_abbrev = ''.join([s.capitalize() for s in rule_name.split(' ')])

rule_file_name = f'{rule_id}_{rule_name.replace(" ", "_")}.go'.lower()
rule_test_file_name = f'{rule_id}_{rule_name.replace(" ", "_")}_test.go'.lower()


rule_template = '''package rule

import (
	"github.com/armosec/kubecop/pkg/approfilecache"
	"github.com/kubescape/kapprofiler/pkg/tracing"
)

const (
	{rule_id}{rule_abbrev}RuleName = "{rule_id} {rule_name}"
)

var {rule_id}{rule_abbrev}RuleDescriptor = RuleDesciptor{
	Name:     {rule_id}{rule_abbrev}RuleName,
	Tags:     []string{},
	Priority: replceme,
	Requirements: RuleRequirements{
		EventTypes:             []tracing.EventType{replaceme},
		NeedApplicationProfile: replaceme,
	},
	RuleCreationFunc: func() Rule {
		return CreateRule{rule_id}{rule_abbrev}()
	},
}

type {rule_id}{rule_abbrev} struct {
}

type {rule_id}{rule_abbrev}Failure struct {
	RuleName     string
    RulePriority int
	Err          string
	FailureEvent *replaceme
}

func (rule *{rule_id}{rule_abbrev}) Name() string {
	return {rule_id}{rule_abbrev}RuleName
}

func CreateRule{rule_id}{rule_abbrev}() *{rule_id}{rule_abbrev} {
	return &{rule_id}{rule_abbrev}{}
}

func (rule *{rule_id}{rule_abbrev}) DeleteRule() {
}

func (rule *{rule_id}{rule_abbrev}) ProcessEvent(eventType tracing.EventType, event interface{}, appProfileAccess approfilecache.SingleApplicationProfileAccess, engineAccess EngineAccess) RuleFailure {
	if eventType != replaceme {
		return nil
	}

	execEvent, ok := event.(*replaceme)
	if !ok {
		return nil
	}

	if appProfileAccess == nil {
		return &{rule_id}{rule_abbrev}Failure{
			RuleName:     rule.Name(),
			Err:          "Application profile is missing",
			FailureEvent: execEvent,
			RulePriority: RulePrioritySystemIssue,
		}
	}

	appProfileExecList, err := appProfileAccess.GetExecList()
	if err != nil || appProfileExecList == nil {
		return &{rule_id}{rule_abbrev}Failure{
			RuleName:     rule.Name(),
			Err:          "Application profile is missing",
			FailureEvent: execEvent,
			RulePriority: RulePrioritySystemIssue,
		}
	}

}

func (rule *{rule_id}{rule_abbrev}) Requirements() RuleRequirements {
	return RuleRequirements{
		EventTypes:             []tracing.EventType{replaceme},
		NeedApplicationProfile: true,
	}
}

func (rule *{rule_id}{rule_abbrev}Failure) Name() string {
	return rule.RuleName
}

func (rule *{rule_id}{rule_abbrev}Failure) Error() string {
	return rule.Err
}

func (rule *{rule_id}{rule_abbrev}Failure) Event() tracing.GeneralEvent {
	return rule.FailureEvent.GeneralEvent
}

func (rule *{rule_id}{rule_abbrev}Failure) Priority() int {
	return rule.RulePriority
}
'''

rule_test_template = '''package rule

import (
	"testing"
)

func Test{rule_id}{rule_abbrev}(t *testing.T) {
	// Create a new rule
	r := CreateRule{rule_id}{rule_abbrev}()
	// Assert r is not nil
	if r == nil {
		t.Errorf("Expected r to not be nil")
	}
}
'''

with open(rule_file_name, 'w') as f:
    rule = rule_template.replace('{rule_id}', rule_id).replace('{rule_name}', rule_name).replace('{rule_abbrev}', rule_abbrev)
    f.write(rule)

with open(rule_test_file_name, 'w') as f:
    rule_test = rule_test_template.replace('{rule_id}', rule_id).replace('{rule_name}', rule_name).replace('{rule_abbrev}', rule_abbrev)
    f.write(rule_test)
