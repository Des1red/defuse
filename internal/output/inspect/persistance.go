package inspect

import (
	"fmt"
	"strings"

	"defuse/internal/knowledge"
	"defuse/internal/output/ui"
)

type persistenceGroup struct {
	Type    string
	Entries []knowledge.Persistence
}

type persistenceField struct {
	Label string
	Value string
}

func writePersistence(
	builder *strings.Builder,
	persistence []knowledge.Persistence,
) {
	ui.Section(
		builder,
		"Persistence Scan",
	)

	if len(persistence) == 0 {
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

	groups :=
		groupPersistence(
			persistence,
		)

	for groupIndex, group := range groups {

		lastGroup :=
			groupIndex ==
				len(groups)-1

		groupName :=
			strings.ToUpper(
				strings.ReplaceAll(
					group.Type,
					"_",
					" ",
				),
			)

		ui.TreeNode(
			builder,
			"",
			lastGroup,
			ui.Accent(
				fmt.Sprintf(
					"%s (%d)",
					groupName,
					len(group.Entries),
				),
			),
		)

		groupPrefix :=
			ui.ChildPrefix(
				"",
				lastGroup,
			)

		for entryIndex, entry := range group.Entries {

			lastEntry :=
				entryIndex ==
					len(group.Entries)-1

			name :=
				entry.Name

			if name == "" {
				name =
					"unnamed"
			}

			ui.TreeNode(
				builder,
				groupPrefix,
				lastEntry,
				ui.Info(
					name,
				),
			)

			fields :=
				[]persistenceField{}

			if entry.Location != "" {
				fields =
					append(
						fields,
						persistenceField{
							Label: "Location",

							Value: entry.Location,
						},
					)
			}

			if entry.Value != "" {
				fields =
					append(
						fields,
						persistenceField{
							Label: "Value",

							Value: entry.Value,
						},
					)
			}

			entryPrefix :=
				ui.ChildPrefix(
					groupPrefix,
					lastEntry,
				)

			for fieldIndex, field := range fields {

				ui.TreeField(
					builder,
					entryPrefix,
					fieldIndex ==
						len(fields)-1,
					field.Label,
					field.Value,
				)
			}
		}
	}
}

func groupPersistence(
	persistence []knowledge.Persistence,
) []persistenceGroup {
	var groups []persistenceGroup

	indices :=
		make(
			map[string]int,
		)

	for _, entry := range persistence {

		index, exists :=
			indices[entry.Type]

		if !exists {
			index =
				len(
					groups,
				)

			indices[entry.Type] =
				index

			groups =
				append(
					groups,
					persistenceGroup{
						Type: entry.Type,
					},
				)
		}

		groups[index].Entries =
			append(
				groups[index].Entries,
				entry,
			)
	}

	return groups
}
