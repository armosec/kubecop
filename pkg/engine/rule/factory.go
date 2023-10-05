package rule

func CreateRules() []IRule {
	return []IRule{
		NewNonWhitelistedExecRule(),
		NewReverseShellRule(),
	}
}
