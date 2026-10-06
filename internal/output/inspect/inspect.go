package inspect

import (
	"fmt"
	"strings"

	"defuse/internal/knowledge"
	"defuse/internal/output/ui"
)

func Print() {
	fmt.Print(
		Render(),
	)
}

func Render() string {
	result :=
		knowledge.Data.Inspect

	var builder strings.Builder

	ui.Title(
		&builder,
		"Inspect",
	)

	writeSummary(
		&builder,
		result,
	)

	writeProcesses(
		&builder,
		result.Processes,
	)

	writeConnections(
		&builder,
		result.Connections,
	)

	writePersistence(
		&builder,
		result.Persistence,
	)

	writeTargets(
		&builder,
		result.Targets,
	)

	if len(result.Errors) > 0 {
		writeErrors(
			&builder,
			result.Errors,
		)
	}

	return builder.String()
}

func writeErrors(
	builder *strings.Builder,
	errors []string,
) {
	ui.Section(
		builder,
		"Errors",
	)

	for index, err := range errors {

		ui.TreeNode(
			builder,
			"",
			index ==
				len(errors)-1,
			ui.Danger(
				err,
			),
		)
	}
}
