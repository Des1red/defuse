package inspect

import (
	"strconv"
	"strings"

	"defuse/internal/knowledge"
	"defuse/internal/output/ui"
)

func writeSummary(
	builder *strings.Builder,
	result knowledge.InspectResult,
) {
	ui.Section(
		builder,
		"Summary",
	)

	targetCount :=
		strconv.Itoa(
			len(
				result.Targets,
			),
		)

	if len(result.Targets) > 0 {
		targetCount =
			ui.Warning(
				targetCount,
			)
	} else {
		targetCount =
			ui.Success(
				targetCount,
			)
	}

	ui.TreeField(
		builder,
		"",
		false,
		"Processes",
		strconv.Itoa(
			len(
				result.Processes,
			),
		),
	)

	ui.TreeField(
		builder,
		"",
		false,
		"Connections",
		strconv.Itoa(
			len(
				result.Connections,
			),
		),
	)

	ui.TreeField(
		builder,
		"",
		false,
		"Persistence",
		strconv.Itoa(
			len(
				result.Persistence,
			),
		),
	)

	ui.TreeField(
		builder,
		"",
		true,
		"Targets",
		targetCount,
	)
}
