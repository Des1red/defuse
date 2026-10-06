//go:build linux

package eradicate

import (
	platform "defuse/internal/engines/eradicate/internal/linux"
	"defuse/internal/knowledge"
)

func eradicateTarget(
	target knowledge.Target,
) Result {
	return platform.Eradicate(
		target,
	)
}
