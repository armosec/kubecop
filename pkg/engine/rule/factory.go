package rule

// List of all rules descriptions.
var ruleDescriptions []RuleDesciptor = []RuleDesciptor{
	R0001UnexpectedProcessLaunchedRuleDescriptor,
	R0002UnexpectedFileAccessRuleDescriptor,
	R0003UnexpectedSystemCallRuleDescriptor,
	R0004UnexpectedCapabilityUsedRuleDescriptor,
	R0005UnexpectedDomainRequestRuleDescriptor,
	R0006UnexpectedServiceAccountTokenAccessRuleDescriptor,
	R0007KubernetesClientExecutedDescriptor,
	R1000ExecFromMaliciousSourceDescriptor,
	R1001ExecBinaryNotInBaseImageRuleDescriptor,
	R1002LoadKernelModuleRuleDescriptor,
	R1003MaliciousSSHConnectionRuleDescriptor,
	R1004ExecFromMountRuleDescriptor,
	R1006UnshareSyscallRuleDescriptor,
	R1007CryptoMinersRuleDescriptor,
}

func GetAllRuleDescriptors() []RuleDesciptor {
	return ruleDescriptions
}

func CreateRulesByTags(tags []string) []Rule {
	var rules []Rule
	for _, rule := range ruleDescriptions {
		if rule.HasTags(tags) {
			rules = append(rules, rule.RuleCreationFunc())
		}
	}
	return rules
}

func CreateRuleByID(id string) Rule {
	for _, rule := range ruleDescriptions {
		if rule.ID == id {
			return rule.RuleCreationFunc()
		}
	}
	return nil
}

func CreateRuleByName(name string) Rule {
	for _, rule := range ruleDescriptions {
		if rule.Name == name {
			return rule.RuleCreationFunc()
		}
	}
	return nil
}

func CreateRulesByNames(names []string) []Rule {
	var rules []Rule
	for _, rule := range ruleDescriptions {
		for _, name := range names {
			if rule.Name == name {
				rules = append(rules, rule.RuleCreationFunc())
			}
		}
	}
	return rules
}
