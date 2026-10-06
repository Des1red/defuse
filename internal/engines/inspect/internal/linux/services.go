//go:build linux

package linux

import (
	"os/exec"
	"strings"

	"defuse/internal/knowledge"
)

func servicePersistence() []knowledge.Persistence {
	var persistence []knowledge.Persistence

	persistence =
		append(
			persistence,
			systemdServices(
				false,
			)...,
		)

	persistence =
		append(
			persistence,
			systemdServices(
				true,
			)...,
		)

	return persistence
}

func systemdServices(
	user bool,
) []knowledge.Persistence {
	var persistence []knowledge.Persistence

	args :=
		[]string{
			"list-unit-files",
			"--type=service",
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

	output, err :=
		exec.Command(
			"systemctl",
			args...,
		).Output()

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

		name :=
			fields[0]

		path,
			command :=
			systemdServiceInfo(
				name,
				user,
			)

		persistence =
			append(
				persistence,
				knowledge.Persistence{
					Type: "service",

					Location: path,

					Name: name,

					Value: command,
				},
			)
	}

	return persistence
}

func systemdServiceInfo(
	name string,
	user bool,
) (
	string,
	string,
) {
	args :=
		[]string{
			"show",
			name,
			"--property=FragmentPath",
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
		return "", ""
	}

	var path string
	var execStart string

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

			path =
				strings.TrimPrefix(
					line,
					"FragmentPath=",
				)

		case strings.HasPrefix(
			line,
			"ExecStart=",
		):

			execStart =
				strings.TrimPrefix(
					line,
					"ExecStart=",
				)
		}
	}

	return path, execStart
}
