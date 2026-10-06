package inspect

import (
	"fmt"
	"strconv"
	"strings"

	"defuse/internal/knowledge"
	"defuse/internal/output/ui"
)

type connectionField struct {
	Label string
	Value string
}

func writeConnections(
	builder *strings.Builder,
	connections []knowledge.Connection,
) {
	ui.Section(
		builder,
		"Network Scan",
	)

	if len(connections) == 0 {
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

	for index, connection := range connections {

		lastConnection :=
			index ==
				len(connections)-1

		ui.TreeNode(
			builder,
			"",
			lastConnection,
			ui.Info(
				fmt.Sprintf(
					"PID %d",
					connection.PID,
				),
			),
		)

		prefix :=
			ui.ChildPrefix(
				"",
				lastConnection,
			)

		fields :=
			[]connectionField{
				{
					Label: "Local",

					Value: address(
						connection.LocalAddress,
						connection.LocalPort,
					),
				},
				{
					Label: "Remote",

					Value: address(
						connection.RemoteAddress,
						connection.RemotePort,
					),
				},
			}

		if connection.State != "" {
			fields =
				append(
					fields,
					connectionField{
						Label: "State",

						Value: connection.State,
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

func address(
	host string,
	port uint16,
) string {
	if host == "" {
		host =
			"*"
	}

	return host +
		":" +
		strconv.FormatUint(
			uint64(
				port,
			),
			10,
		)
}
