//go:build windows

package windows

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

	files :=
		fileCandidates(
			target,
		)

	/*
		Windows does not use the Linux SIGSTOP stage.

		The validated target cluster is terminated first so that
		the malware cannot continue rewriting persistence while
		cleanup is taking place.

		If anything manages to respawn during that small window,
		the path-based sweep below finds and terminates it again.
	*/
	terminateCluster(
		active,
		&result,
	)

	removePersistence(
		target,
		&result,
	)

	time.Sleep(
		100 * time.Millisecond,
	)

	sweep :=
		discoverProcessesByPath(
			files,
		)

	if len(sweep) > 0 {
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
		250 * time.Millisecond,
	)

	result.Verified =
		verify(
			cluster,
			target.Persistence,
			files,
			target,
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
