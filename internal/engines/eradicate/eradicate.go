package eradicate

import "defuse/internal/knowledge"

func Eradicate() Result {
	var result Result

	if knowledge.Data.Target == nil {
		result.Errors =
			append(
				result.Errors,
				"no target available",
			)

		return result
	}

	return eradicateTarget(
		*knowledge.Data.Target,
	)
}
