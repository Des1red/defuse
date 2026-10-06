//go:build linux

package linux

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"defuse/internal/knowledge"
)

func verify(
	cluster []knowledge.Process,
	persistence []knowledge.Persistence,
	files []string,
) bool {
	for _, process := range cluster {

		running,
			err :=
			validateProcess(
				process,
			)

		if err != nil ||
			running {

			return false
		}
	}

	if len(
		discoverProcessesByPath(
			files,
		),
	) > 0 {

		return false
	}

	for _, entry := range persistence {

		if persistenceExists(
			entry,
		) {
			return false
		}
	}

	for _, path := range files {

		if _, err :=
			os.Lstat(
				path,
			); err == nil {

			return false
		}
	}

	return true
}

func persistenceExists(
	entry knowledge.Persistence,
) bool {
	switch entry.Type {
	case "autostart",
		"service",
		"timer":

		if entry.Location == "" {
			return true
		}

		_, err :=
			os.Lstat(
				entry.Location,
			)

		return err == nil

	case "cron":
		return cronEntryExists(
			entry,
		)

	default:
		return true
	}
}

func cronEntryExists(
	entry knowledge.Persistence,
) bool {
	if entry.Location ==
		"user crontab" {

		output, err :=
			exec.Command(
				"crontab",
				"-l",
			).Output()

		if err != nil {
			return false
		}

		return containsExactLine(
			string(
				output,
			),
			entry.Value,
		)
	}

	info, err :=
		os.Stat(
			entry.Location,
		)

	if err == nil &&
		info.IsDir() {

		_, err =
			os.Lstat(
				filepath.Join(
					entry.Location,
					entry.Name,
				),
			)

		return err == nil
	}

	data, err :=
		os.ReadFile(
			entry.Location,
		)

	if err != nil {
		return false
	}

	return containsExactLine(
		string(
			data,
		),
		entry.Value,
	)
}

func containsExactLine(
	content string,
	value string,
) bool {
	value =
		strings.TrimSpace(
			value,
		)

	for _, line := range strings.Split(
		content,
		"\n",
	) {

		if strings.TrimSpace(
			line,
		) ==
			value {

			return true
		}
	}

	return false
}
