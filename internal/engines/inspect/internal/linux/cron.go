//go:build linux

package linux

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"defuse/internal/knowledge"
)

func cronPersistence() []knowledge.Persistence {
	var persistence []knowledge.Persistence

	persistence =
		append(
			persistence,
			cronFile(
				"/etc/crontab",
			)...,
		)

	cronD :=
		"/etc/cron.d"

	entries, err :=
		os.ReadDir(
			cronD,
		)

	if err == nil {
		for _, entry := range entries {

			if entry.IsDir() {
				continue
			}

			path :=
				filepath.Join(
					cronD,
					entry.Name(),
				)

			persistence =
				append(
					persistence,
					cronFile(
						path,
					)...,
				)
		}
	}

	directories :=
		[]string{
			"/etc/cron.hourly",
			"/etc/cron.daily",
			"/etc/cron.weekly",
			"/etc/cron.monthly",
		}

	for _, directory := range directories {

		persistence =
			append(
				persistence,
				cronDirectory(
					directory,
				)...,
			)
	}

	persistence =
		append(
			persistence,
			userCronPersistence()...,
		)

	persistence =
		append(
			persistence,
			cronSpoolPersistence()...,
		)

	return persistence
}

func cronFile(
	path string,
) []knowledge.Persistence {
	var persistence []knowledge.Persistence

	file, err :=
		os.Open(
			path,
		)

	if err != nil {
		return persistence
	}

	defer file.Close()

	scanner :=
		bufio.NewScanner(
			file,
		)

	lineNumber := 0

	for scanner.Scan() {
		lineNumber++

		line :=
			strings.TrimSpace(
				scanner.Text(),
			)

		if line == "" ||
			strings.HasPrefix(
				line,
				"#",
			) {

			continue
		}

		fields :=
			strings.Fields(
				line,
			)

		if len(fields) == 0 {
			continue
		}

		if strings.Contains(
			fields[0],
			"=",
		) {
			continue
		}

		persistence =
			append(
				persistence,
				knowledge.Persistence{
					Type: "cron",

					Location: path,

					Name: fmt.Sprintf(
						"line %d",
						lineNumber,
					),

					Value: line,
				},
			)
	}

	return persistence
}

func cronDirectory(
	path string,
) []knowledge.Persistence {
	var persistence []knowledge.Persistence

	entries, err :=
		os.ReadDir(
			path,
		)

	if err != nil {
		return persistence
	}

	for _, entry := range entries {

		if entry.IsDir() {
			continue
		}

		file :=
			filepath.Join(
				path,
				entry.Name(),
			)

		persistence =
			append(
				persistence,
				knowledge.Persistence{
					Type: "cron",

					Location: path,

					Name: entry.Name(),

					Value: file,
				},
			)
	}

	return persistence
}

func userCronPersistence() []knowledge.Persistence {
	var persistence []knowledge.Persistence

	output, err :=
		exec.Command(
			"crontab",
			"-l",
		).Output()

	if err != nil {
		return persistence
	}

	lines :=
		strings.Split(
			string(output),
			"\n",
		)

	for index, line := range lines {

		line =
			strings.TrimSpace(
				line,
			)

		if line == "" ||
			strings.HasPrefix(
				line,
				"#",
			) {

			continue
		}

		persistence =
			append(
				persistence,
				knowledge.Persistence{
					Type: "cron",

					Location: "user crontab",

					Name: fmt.Sprintf(
						"line %d",
						index+1,
					),

					Value: line,
				},
			)
	}

	return persistence
}

func cronSpoolPersistence() []knowledge.Persistence {
	var persistence []knowledge.Persistence

	directories :=
		[]string{
			"/var/spool/cron",
			"/var/spool/cron/crontabs",
		}

	for _, directory := range directories {

		entries, err :=
			os.ReadDir(
				directory,
			)

		if err != nil {
			continue
		}

		for _, entry := range entries {

			if entry.IsDir() {
				continue
			}

			path :=
				filepath.Join(
					directory,
					entry.Name(),
				)

			persistence =
				append(
					persistence,
					cronFile(
						path,
					)...,
				)
		}
	}

	return persistence
}
