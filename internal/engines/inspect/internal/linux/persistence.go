//go:build linux

package linux

import "defuse/internal/knowledge"

func Persistence() []knowledge.Persistence {
	var persistence []knowledge.Persistence

	persistence =
		append(
			persistence,
			autostartPersistence()...,
		)

	persistence =
		append(
			persistence,
			cronPersistence()...,
		)

	persistence =
		append(
			persistence,
			servicePersistence()...,
		)

	persistence =
		append(
			persistence,
			scheduledPersistence()...,
		)

	return persistence
}
