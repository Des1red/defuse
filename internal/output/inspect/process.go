package inspect

import (
	"fmt"
	"strconv"
	"strings"

	"defuse/internal/knowledge"
	"defuse/internal/output/ui"
)

type processField struct {
	Label string
	Value string
}

func writeProcesses(
	builder *strings.Builder,
	processes []knowledge.Process,
) {
	ui.Section(
		builder,
		"Process Scan",
	)

	if len(processes) == 0 {
		ui.TreeNode(
			builder,
			"",
			true,
			ui.Muted(
				"none",
			),
		)

		return
	}

	for index, process := range processes {

		lastProcess :=
			index ==
				len(processes)-1

		name :=
			process.Name

		if name == "" {
			name =
				"unknown"
		}

		ui.TreeNode(
			builder,
			"",
			lastProcess,
			ui.Info(
				fmt.Sprintf(
					"[%d] %s",
					process.PID,
					name,
				),
			),
		)

		prefix :=
			ui.ChildPrefix(
				"",
				lastProcess,
			)

		fields :=
			[]processField{
				{
					Label: "Parent PID",

					Value: strconv.FormatUint(
						uint64(
							process.PPID,
						),
						10,
					),
				},
			}

		if process.Path != "" {
			fields =
				append(
					fields,
					processField{
						Label: "Path",

						Value: process.Path,
					},
				)
		}

		if process.CommandLine != "" {
			fields =
				append(
					fields,
					processField{
						Label: "Command",

						Value: process.CommandLine,
					},
				)
		}

		for fieldIndex, field := range fields {

			ui.TreeField(
				builder,
				prefix,
				fieldIndex ==
					len(fields)-1,
				field.Label,
				field.Value,
			)
		}
	}
}
