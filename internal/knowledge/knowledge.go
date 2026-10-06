package knowledge

type Knowledge struct {
	Inspect InspectResult

	Target *Target

	Eradicate EradicateResult
}

var Data Knowledge
