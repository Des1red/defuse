package knowledge

type Action struct {
	Type string

	Target string

	Success bool

	Error string
}

type EradicateResult struct {
	Actions []Action

	Verified bool

	Errors []string
}
