package eradicate

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
		knowledge.Data.Eradicate

	var builder strings.Builder

	ui.Title(
		&builder,
		"Eradicate",
	)

	for _, action := range result.Actions {

		status :=
			ui.Danger(
				"failed",
			)

		if action.Success {
			status =
				ui.Success(
					"success",
				)
		}

		ui.Field(
			&builder,
			action.Type,
			fmt.Sprintf(
				"%s [%s]",
				action.Target,
				status,
			),
		)

		if action.Error != "" {
			ui.IndentedField(
				&builder,
				"Error",
				action.Error,
			)
		}
	}

	if result.Verified {
		ui.Field(
			&builder,
			"Verification",
			ui.Success(
				"passed",
			),
		)
	} else {
		ui.Field(
			&builder,
			"Verification",
			ui.Warning(
				"not verified",
			),
		)
	}

	for _, err := range result.Errors {

		ui.Bullet(
			&builder,
			ui.Danger(
				err,
			),
		)
	}

	return builder.String()
}
