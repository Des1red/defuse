//go:build linux

package linux

import (
	"os/exec"
	"strings"

	"defuse/internal/knowledge"
)

func scheduledPersistence() []knowledge.Persistence {
	var persistence []knowledge.Persistence

	persistence =
		append(
			persistence,
			systemTimers(
				false,
			)...,
		)

	persistence =
		append(
			persistence,
			systemTimers(
				true,
			)...,
		)

	return persistence
}

func systemTimers(
	user bool,
) []knowledge.Persistence {
	var persistence []knowledge.Persistence

	args :=
		[]string{
			"list-unit-files",
			"--type=timer",
			"--state=enabled",
			"--no-legend",
			"--no-pager",
		}

	if user {
		args =
			append(
				[]string{
					"--user",
				},
				args...,
			)
	}

	command :=
		exec.Command(
			"systemctl",
			args...,
		)

	output, err :=
		command.Output()

	if err != nil {
		return persistence
	}

	lines :=
		strings.Split(
			string(output),
			"\n",
		)

	for _, line := range lines {

		fields :=
			strings.Fields(
				line,
			)

		if len(fields) == 0 {
			continue
		}

		timer :=
			fields[0]

		location,
			service :=
			timerInfo(
				timer,
				user,
			)

		command :=
			serviceCommand(
				service,
				user,
			)

		persistence =
			append(
				persistence,
				knowledge.Persistence{
					Type: "timer",

					Location: location,

					Name: timer,

					Value: command,
				},
			)
	}

	return persistence
}

func timerInfo(
	timer string,
	user bool,
) (
	string,
	string,
) {
	args :=
		[]string{
			"show",
			timer,
			"--property=FragmentPath",
			"--property=Unit",
			"--no-pager",
		}

	if user {
		args =
			append(
				[]string{
					"--user",
				},
				args...,
			)
	}

	output, err :=
		exec.Command(
			"systemctl",
			args...,
		).Output()

	if err != nil {
		return "", ""
	}

	var location string
	var service string

	lines :=
		strings.Split(
			string(output),
			"\n",
		)

	for _, line := range lines {

		switch {
		case strings.HasPrefix(
			line,
			"FragmentPath=",
		):

			location =
				strings.TrimPrefix(
					line,
					"FragmentPath=",
				)

		case strings.HasPrefix(
			line,
			"Unit=",
		):

			service =
				strings.TrimPrefix(
					line,
					"Unit=",
				)
		}
	}

	if service == "" {
		service =
			strings.TrimSuffix(
				timer,
				".timer",
			) +
				".service"
	}

	return location, service
}

func serviceCommand(
	service string,
	user bool,
) string {
	if service == "" {
		return ""
	}

	args :=
		[]string{
			"show",
			service,
			"--property=ExecStart",
			"--no-pager",
		}

	if user {
		args =
			append(
				[]string{
					"--user",
				},
				args...,
			)
	}

	output, err :=
		exec.Command(
			"systemctl",
			args...,
		).Output()

	if err != nil {
		return ""
	}

	lines :=
		strings.Split(
			string(output),
			"\n",
		)

	for _, line := range lines {

		if !strings.HasPrefix(
			line,
			"ExecStart=",
		) {
			continue
		}

		return strings.TrimPrefix(
			line,
			"ExecStart=",
		)
	}

	return ""
}
