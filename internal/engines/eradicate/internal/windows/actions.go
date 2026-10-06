//go:build windows

package windows

import (
	"fmt"

	"defuse/internal/knowledge"
)

func processLabel(
	process knowledge.Process,
) string {
	if process.Name == "" {
		return fmt.Sprintf(
			"PID %d",
			process.PID,
		)
	}

	return fmt.Sprintf(
		"PID %d %s",
		process.PID,
		process.Name,
	)
}

func persistenceLabel(
	entry knowledge.Persistence,
) string {
	if entry.Name == "" {
		return entry.Type
	}

	return fmt.Sprintf(
		"%s %s",
		entry.Type,
		entry.Name,
	)
}

func appendAction(
	result *knowledge.EradicateResult,
	actionType string,
	target string,
	err error,
) {
	action :=
		knowledge.Action{
			Type: actionType,

			Target: target,

			Success: err == nil,
		}

	if err != nil {
		action.Error =
			err.Error()

		result.Errors =
			append(
				result.Errors,
				fmt.Sprintf(
					"%s %s: %v",
					actionType,
					target,
					err,
				),
			)
	}

	result.Actions =
		append(
			result.Actions,
			action,
		)
}
