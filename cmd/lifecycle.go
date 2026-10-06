package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"defuse/internal"
	"defuse/internal/knowledge"
	"defuse/internal/models"
	"defuse/internal/output"
	"defuse/internal/output/ui"
)

func controller() {
	internal.Controller()

	prompt()

	save()
}

func save() {
	path, err :=
		output.Save()

	if err != nil {
		fmt.Println(
			ui.Danger(
				"Failed to save report: " +
					err.Error(),
			),
		)

		return
	}

	if path == "" {
		return
	}

	fmt.Printf(
		"\n%s %s\n",
		ui.Success(
			"Report saved:",
		),
		path,
	)
}

func prompt() {
	if !models.Engines.Inspect.Complete {
		return
	}

	if models.Engines.Eradicate.Complete {
		return
	}

	targets :=
		knowledge.Data.Inspect.Targets

	if len(targets) == 0 {
		return
	}

	index, ok :=
		selectTarget(
			targets,
		)

	if !ok {
		return
	}

	target :=
		&knowledge.Data.Inspect.Targets[index]

	if !confirmEradication(
		target,
	) {
		return
	}

	knowledge.Data.Target =
		target

	models.Engines.Eradicate.Active =
		true

	internal.Controller()
}

func selectTarget(
	targets []knowledge.Target,
) (
	int,
	bool,
) {
	if len(targets) == 1 {
		return 0, true
	}

	reader :=
		bufio.NewReader(
			os.Stdin,
		)

	for {
		fmt.Printf(
			"\n%s ",
			ui.Warning(
				"Select target ID to eradicate [Enter to cancel]:",
			),
		)

		input, err :=
			reader.ReadString(
				'\n',
			)

		if err != nil {
			return 0, false
		}

		input =
			strings.TrimSpace(
				input,
			)

		if input == "" {
			return 0, false
		}

		id, err :=
			strconv.Atoi(
				input,
			)

		if err != nil {
			fmt.Println(
				ui.Danger(
					"Invalid target ID.",
				),
			)

			continue
		}

		for index := range targets {

			if targets[index].ID == id {
				return index, true
			}
		}

		fmt.Println(
			ui.Danger(
				"Target not found.",
			),
		)
	}
}

func confirmEradication(
	target *knowledge.Target,
) bool {
	reader :=
		bufio.NewReader(
			os.Stdin,
		)

	fmt.Printf(
		"\n%s\n",
		ui.Danger(
			fmt.Sprintf(
				"Target #%d: %s [PID %d]",
				target.ID,
				target.Process.Name,
				target.Process.PID,
			),
		),
	)

	fmt.Printf(
		"%s ",
		ui.Warning(
			"Hunt down and completely remove this target? [y/N]:",
		),
	)

	input, err :=
		reader.ReadString(
			'\n',
		)

	if err != nil {
		return false
	}

	input =
		strings.ToLower(
			strings.TrimSpace(
				input,
			),
		)

	return input == "y" ||
		input == "yes"
}
