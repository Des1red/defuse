//go:build windows

package eradicate

import (
	platform "defuse/internal/engines/eradicate/internal/windows"
	"defuse/internal/knowledge"
)

func eradicateTarget(
	target knowledge.Target,
) Result {
	return platform.Eradicate(
		target,
	)
}
