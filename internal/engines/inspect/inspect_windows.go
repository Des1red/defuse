//go:build windows

package inspect

import (
	platform "defuse/internal/engines/inspect/internal/windows"
	shared "defuse/internal/engines/shared"
)

func Inspect() Result {
	var result Result

	result.Processes =
		platform.Processes()

	result.Connections =
		shared.Connections()

	result.Persistence =
		platform.Persistence()

	result.Targets =
		platform.Correlate(
			result.Processes,
			result.Connections,
			result.Persistence,
		)

	return result
}
