//go:build !linux && !windows

package eradicate

import (
	"fmt"

	"defuse/internal/knowledge"
)

func eradicateTarget(
	target knowledge.Target,
) Result {
	var result Result

	result.Errors =
		append(
			result.Errors,
			fmt.Sprintf(
				"eradication is not implemented for this platform for target %d",
				target.ID,
			),
		)

	return result
}
