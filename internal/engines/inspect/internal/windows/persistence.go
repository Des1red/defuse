//go:build windows

package windows

import "defuse/internal/knowledge"

func Persistence() []knowledge.Persistence {
	var persistence []knowledge.Persistence

	persistence =
		append(
			persistence,
			registryPersistence()...,
		)

	persistence =
		append(
			persistence,
			startupPersistence()...,
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

	persistence =
		append(
			persistence,
			winlogonPersistence()...,
		)

	persistence =
		append(
			persistence,
			appInitPersistence()...,
		)

	persistence =
		append(
			persistence,
			imageHijackPersistence()...,
		)
	return persistence
}
