//go:build linux

package linux

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"defuse/internal/knowledge"
)

func removePersistence(
	persistence []knowledge.Persistence,
	result *knowledge.EradicateResult,
) {
	for _, entry := range persistence {

		err :=
			removePersistenceEntry(
				entry,
			)

		appendAction(
			result,
			"remove_persistence",
			persistenceLabel(
				entry,
			),
			err,
		)
	}
}

func removePersistenceEntry(
	entry knowledge.Persistence,
) error {
	switch entry.Type {
	case "autostart":
		return removeFile(
			entry.Location,
		)

	case "service":
		return removeSystemdUnit(
			entry,
		)

	case "timer":
		return removeSystemdUnit(
			entry,
		)

	case "cron":
		return removeCron(
			entry,
		)

	default:
		return fmt.Errorf(
			"unsupported persistence type %q",
			entry.Type,
		)
	}
}

func removeSystemdUnit(
	entry knowledge.Persistence,
) error {
	user :=
		isUserSystemdPath(
			entry.Location,
		)

	args :=
		[]string{
			"disable",
			entry.Name,
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

	output, disableErr :=
		exec.Command(
			"systemctl",
			args...,
		).CombinedOutput()

	removeErr :=
		removeFile(
			entry.Location,
		)

	reloadArgs :=
		[]string{
			"daemon-reload",
		}

	if user {
		reloadArgs =
			append(
				[]string{
					"--user",
				},
				reloadArgs...,
			)
	}

	_ =
		exec.Command(
			"systemctl",
			reloadArgs...,
		).Run()

	if disableErr != nil {
		message :=
			strings.TrimSpace(
				string(
					output,
				),
			)

		if message == "" {
			message =
				disableErr.Error()
		}

		if removeErr != nil {
			return fmt.Errorf(
				"disable failed: %s; remove failed: %v",
				message,
				removeErr,
			)
		}

		return fmt.Errorf(
			"disable failed: %s",
			message,
		)
	}

	return removeErr
}

func isUserSystemdPath(
	path string,
) bool {
	return strings.Contains(
		path,
		"/.config/systemd/user/",
	) ||
		strings.Contains(
			path,
			"/.local/share/systemd/user/",
		)
}

func removeCron(
	entry knowledge.Persistence,
) error {
	if entry.Location ==
		"user crontab" {

		return removeUserCronLine(
			entry.Value,
		)
	}

	info, err :=
		os.Stat(
			entry.Location,
		)

	if err == nil &&
		info.IsDir() {

		path :=
			filepath.Join(
				entry.Location,
				entry.Name,
			)

		return removeFile(
			path,
		)
	}

	if err != nil &&
		!os.IsNotExist(
			err,
		) {

		return err
	}

	return removeLineFromFile(
		entry.Location,
		entry.Value,
	)
}

func removeUserCronLine(
	value string,
) error {
	if _, err :=
		exec.LookPath(
			"crontab",
		); err != nil {

		return err
	}

	output, err :=
		exec.Command(
			"crontab",
			"-l",
		).Output()

	if err != nil {
		return nil
	}

	updated,
		changed :=
		removeExactLine(
			string(
				output,
			),
			value,
		)

	if !changed {
		return nil
	}

	command :=
		exec.Command(
			"crontab",
			"-",
		)

	command.Stdin =
		strings.NewReader(
			updated,
		)

	return command.Run()
}

func removeLineFromFile(
	path string,
	value string,
) error {
	if path == "" {
		return errors.New(
			"cron file path is empty",
		)
	}

	data, err :=
		os.ReadFile(
			path,
		)

	if err != nil {
		if os.IsNotExist(
			err,
		) {
			return nil
		}

		return err
	}

	updated,
		changed :=
		removeExactLine(
			string(
				data,
			),
			value,
		)

	if !changed {
		return nil
	}

	info, err :=
		os.Stat(
			path,
		)

	if err != nil {
		return err
	}

	return os.WriteFile(
		path,
		[]byte(
			updated,
		),
		info.Mode().Perm(),
	)
}

func removeExactLine(
	content string,
	target string,
) (
	string,
	bool,
) {
	lines :=
		strings.Split(
			content,
			"\n",
		)

	target =
		strings.TrimSpace(
			target,
		)

	var output []string

	removed :=
		false

	for _, line := range lines {

		if !removed &&
			strings.TrimSpace(
				line,
			) ==
				target {

			removed =
				true

			continue
		}

		output =
			append(
				output,
				line,
			)
	}

	return strings.Join(
		output,
		"\n",
	), removed
}
