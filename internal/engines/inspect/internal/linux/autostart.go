//go:build linux

package linux

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"defuse/internal/knowledge"
)

func autostartPersistence() []knowledge.Persistence {
	var persistence []knowledge.Persistence

	var locations []string

	home, err :=
		os.UserHomeDir()

	if err == nil {
		locations =
			append(
				locations,
				filepath.Join(
					home,
					".config",
					"autostart",
				),
			)
	}

	locations =
		append(
			locations,
			"/etc/xdg/autostart",
		)

	for _, location := range locations {

		entries, err :=
			os.ReadDir(
				location,
			)

		if err != nil {
			continue
		}

		for _, entry := range entries {

			if entry.IsDir() {
				continue
			}

			if filepath.Ext(
				entry.Name(),
			) != ".desktop" {

				continue
			}

			path :=
				filepath.Join(
					location,
					entry.Name(),
				)

			persistence =
				append(
					persistence,
					knowledge.Persistence{
						Type: "autostart",

						Location: path,

						Name: entry.Name(),

						Value: desktopExec(
							path,
						),
					},
				)
		}
	}

	return persistence
}

func desktopExec(
	path string,
) string {
	file, err :=
		os.Open(
			path,
		)

	if err != nil {
		return ""
	}

	defer file.Close()

	scanner :=
		bufio.NewScanner(
			file,
		)

	for scanner.Scan() {
		line :=
			strings.TrimSpace(
				scanner.Text(),
			)

		if !strings.HasPrefix(
			line,
			"Exec=",
		) {
			continue
		}

		return strings.TrimPrefix(
			line,
			"Exec=",
		)
	}

	return ""
}
