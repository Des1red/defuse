package inspect

import (
	"fmt"
	"strconv"
	"strings"

	"defuse/internal/knowledge"
	"defuse/internal/output/ui"
)

func writeTargets(
	builder *strings.Builder,
	targets []knowledge.Target,
) {
	ui.Section(
		builder,
		"Correlation Results",
	)

	if len(targets) == 0 {
		ui.TreeNode(
			builder,
			"",
			true,
			ui.Success(
				"no suspicious targets detected",
			),
		)

		return
	}

	for index, target := range targets {

		writeTarget(
			builder,
			target,
			index ==
				len(targets)-1,
		)
	}
}

func writeTarget(
	builder *strings.Builder,
	target knowledge.Target,
	lastTarget bool,
) {
	name :=
		target.Process.Name

	if name == "" {
		name =
			"unknown"
	}

	heading :=
		ui.Danger(
			fmt.Sprintf(
				"Target #%d",
				target.ID,
			),
		) +
			" " +
			confidence(
				target.Confidence,
			) +
			" " +
			ui.Info(
				name,
			)

	ui.TreeNode(
		builder,
		"",
		lastTarget,
		heading,
	)

	prefix :=
		ui.ChildPrefix(
			"",
			lastTarget,
		)

	childCount := 0

	if target.Process.PID != 0 {
		childCount++
	}

	if target.Process.Path != "" {
		childCount++
	}

	if target.Process.CommandLine != "" {
		childCount++
	}

	if len(target.Findings) > 0 {
		childCount++
	}

	if len(target.IPAddresses) > 0 {
		childCount++
	}

	if len(target.Connections) > 0 {
		childCount++
	}

	if len(target.Persistence) > 0 {
		childCount++
	}

	if len(target.RelatedProcesses) > 0 {
		childCount++
	}

	childIndex := 0

	nextLast :=
		func() bool {
			childIndex++

			return childIndex ==
				childCount
		}

	if target.Process.PID != 0 {
		ui.TreeField(
			builder,
			prefix,
			nextLast(),
			"PID",
			strconv.FormatUint(
				uint64(
					target.Process.PID,
				),
				10,
			),
		)
	}

	if target.Process.Path != "" {
		ui.TreeField(
			builder,
			prefix,
			nextLast(),
			"Path",
			target.Process.Path,
		)
	}

	if target.Process.CommandLine != "" {
		ui.TreeField(
			builder,
			prefix,
			nextLast(),
			"Command",
			target.Process.CommandLine,
		)
	}

	if len(target.Findings) > 0 {
		writeTargetFindings(
			builder,
			prefix,
			nextLast(),
			target.Findings,
		)
	}

	if len(target.IPAddresses) > 0 {
		writeTargetIPAddresses(
			builder,
			prefix,
			nextLast(),
			target.IPAddresses,
		)
	}

	if len(target.Connections) > 0 {
		writeTargetConnections(
			builder,
			prefix,
			nextLast(),
			target.Connections,
		)
	}

	if len(target.Persistence) > 0 {
		writeTargetPersistence(
			builder,
			prefix,
			nextLast(),
			target.Persistence,
		)
	}

	if len(target.RelatedProcesses) > 0 {
		writeRelatedProcesses(
			builder,
			prefix,
			nextLast(),
			target.RelatedProcesses,
		)
	}
}

func writeTargetFindings(
	builder *strings.Builder,
	prefix string,
	last bool,
	findings []knowledge.Finding,
) {
	ui.TreeNode(
		builder,
		prefix,
		last,
		ui.Accent(
			"Findings",
		),
	)

	childPrefix :=
		ui.ChildPrefix(
			prefix,
			last,
		)

	for index, finding := range findings {

		ui.TreeNode(
			builder,
			childPrefix,
			index ==
				len(findings)-1,
			ui.Warning(
				fmt.Sprintf(
					"[%s]",
					finding.Type,
				),
			)+
				" "+
				finding.Reason,
		)
	}
}

func writeTargetIPAddresses(
	builder *strings.Builder,
	prefix string,
	last bool,
	addresses []string,
) {
	ui.TreeNode(
		builder,
		prefix,
		last,
		ui.Accent(
			"IP Indicators",
		),
	)

	childPrefix :=
		ui.ChildPrefix(
			prefix,
			last,
		)

	for index, address := range addresses {

		ui.TreeNode(
			builder,
			childPrefix,
			index ==
				len(addresses)-1,
			ui.Info(
				address,
			),
		)
	}
}

func writeTargetConnections(
	builder *strings.Builder,
	prefix string,
	last bool,
	connections []knowledge.Connection,
) {
	ui.TreeNode(
		builder,
		prefix,
		last,
		ui.Accent(
			"Connections",
		),
	)

	childPrefix :=
		ui.ChildPrefix(
			prefix,
			last,
		)

	for index, connection := range connections {

		value :=
			fmt.Sprintf(
				"PID %d %s -> %s",
				connection.PID,
				address(
					connection.LocalAddress,
					connection.LocalPort,
				),
				address(
					connection.RemoteAddress,
					connection.RemotePort,
				),
			)

		if connection.State != "" {
			value +=
				" [" +
					connection.State +
					"]"
		}

		ui.TreeNode(
			builder,
			childPrefix,
			index ==
				len(connections)-1,
			value,
		)
	}
}

func writeTargetPersistence(
	builder *strings.Builder,
	prefix string,
	last bool,
	persistence []knowledge.Persistence,
) {
	ui.TreeNode(
		builder,
		prefix,
		last,
		ui.Accent(
			"Persistence",
		),
	)

	childPrefix :=
		ui.ChildPrefix(
			prefix,
			last,
		)

	for index, entry := range persistence {

		entryLast :=
			index ==
				len(persistence)-1

		name :=
			entry.Name

		if name == "" {
			name =
				"unnamed"
		}

		ui.TreeNode(
			builder,
			childPrefix,
			entryLast,
			ui.Info(
				fmt.Sprintf(
					"[%s] %s",
					entry.Type,
					name,
				),
			),
		)

		detailPrefix :=
			ui.ChildPrefix(
				childPrefix,
				entryLast,
			)

		detailCount := 0

		if entry.Location != "" {
			detailCount++
		}

		if entry.Value != "" {
			detailCount++
		}

		detailIndex := 0

		if entry.Location != "" {
			detailIndex++

			ui.TreeField(
				builder,
				detailPrefix,
				detailIndex ==
					detailCount,
				"Location",
				entry.Location,
			)
		}

		if entry.Value != "" {
			detailIndex++

			ui.TreeField(
				builder,
				detailPrefix,
				detailIndex ==
					detailCount,
				"Value",
				entry.Value,
			)
		}
	}
}

func writeRelatedProcesses(
	builder *strings.Builder,
	prefix string,
	last bool,
	processes []knowledge.Process,
) {
	ui.TreeNode(
		builder,
		prefix,
		last,
		ui.Accent(
			"Related Processes",
		),
	)

	childPrefix :=
		ui.ChildPrefix(
			prefix,
			last,
		)

	for index, process := range processes {

		processLast :=
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
			childPrefix,
			processLast,
			ui.Info(
				fmt.Sprintf(
					"[%d] %s",
					process.PID,
					name,
				),
			),
		)

		fieldCount := 0

		if process.Path != "" {
			fieldCount++
		}

		if process.CommandLine != "" {
			fieldCount++
		}

		if fieldCount == 0 {
			continue
		}

		detailPrefix :=
			ui.ChildPrefix(
				childPrefix,
				processLast,
			)

		fieldIndex := 0

		if process.Path != "" {
			fieldIndex++

			ui.TreeField(
				builder,
				detailPrefix,
				fieldIndex ==
					fieldCount,
				"Path",
				process.Path,
			)
		}

		if process.CommandLine != "" {
			fieldIndex++

			ui.TreeField(
				builder,
				detailPrefix,
				fieldIndex ==
					fieldCount,
				"Command",
				process.CommandLine,
			)
		}
	}
}

func confidence(
	value string,
) string {
	switch strings.ToLower(
		value,
	) {
	case "high":
		return ui.Danger(
			"[HIGH]",
		)

	case "medium":
		return ui.Warning(
			"[MEDIUM]",
		)

	default:
		return ui.Info(
			"[LOW]",
		)
	}
}
