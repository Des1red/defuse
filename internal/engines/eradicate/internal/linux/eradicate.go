//go:build linux

package linux

import (
	"fmt"
	"time"

	"defuse/internal/knowledge"
)

func Eradicate(
	target knowledge.Target,
) knowledge.EradicateResult {
	var result knowledge.EradicateResult

	cluster :=
		processCluster(
			target,
		)

	active,
		valid :=
		validateCluster(
			cluster,
			&result,
		)

	if !valid {
		return result
	}

	freezeCluster(
		active,
		&result,
	)

	removePersistence(
		target.Persistence,
		&result,
	)

	terminateCluster(
		active,
		&result,
	)

	files :=
		fileCandidates(
			target,
		)

	/*
		A process may have been recreated during the very small
		window before the whole original cluster was frozen.

		Sweep for processes executing from the confirmed malicious
		executable paths before deleting the files.
	*/
	sweep :=
		discoverProcessesByPath(
			files,
		)

	if len(sweep) > 0 {
		freezeCluster(
			sweep,
			&result,
		)

		terminateCluster(
			sweep,
			&result,
		)
	}

	removeFiles(
		files,
		&result,
	)

	time.Sleep(
		150 * time.Millisecond,
	)

	result.Verified =
		verify(
			cluster,
			target.Persistence,
			files,
		)

	result.Actions =
		append(
			result.Actions,
			knowledge.Action{
				Type: "verify",

				Target: fmt.Sprintf(
					"target #%d",
					target.ID,
				),

				Success: result.Verified,
			},
		)

	if !result.Verified {
		result.Errors =
			append(
				result.Errors,
				"eradication verification failed",
			)
	}

	return result
}
