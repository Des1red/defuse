//go:build windows

package windows

import (
	"os"
	"path/filepath"

	"defuse/internal/knowledge"
)

func startupPersistence() []knowledge.Persistence {
	var persistence []knowledge.Persistence

	var locations []string

	appData :=
		os.Getenv(
			"APPDATA",
		)

	if appData != "" {
		locations =
			append(
				locations,
				filepath.Join(
					appData,
					"Microsoft",
					"Windows",
					"Start Menu",
					"Programs",
					"Startup",
				),
			)
	}

	programData :=
		os.Getenv(
			"ProgramData",
		)

	if programData != "" {
		locations =
			append(
				locations,
				filepath.Join(
					programData,
					"Microsoft",
					"Windows",
					"Start Menu",
					"Programs",
					"StartUp",
				),
			)
	}

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

			path :=
				filepath.Join(
					location,
					entry.Name(),
				)

			persistence =
				append(
					persistence,
					knowledge.Persistence{
						Type: "startup",

						Location: location,

						Name: entry.Name(),

						Value: path,
					},
				)
		}
	}

	return persistence
}
