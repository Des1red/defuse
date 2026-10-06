//go:build linux

package linux

import (
	"os"
	"path/filepath"
	"strings"

	shared "defuse/internal/engines/shared"
	"defuse/internal/knowledge"
)

func appendOrphanPersistenceTargets(
	targets []knowledge.Target,
	persistence []knowledge.Persistence,
) []knowledge.Target {
	used :=
		usedPersistence(
			targets,
		)

	groups :=
		make(
			map[string][]knowledge.Persistence,
		)

	var order []string

	for _, entry := range persistence {

		if _, exists :=
			used[persistenceKey(
				entry,
			)]; exists {

			continue
		}

		path,
			ok :=
			linuxPersistenceExecutable(
				entry,
			)

		if !ok {
			continue
		}

		path =
			normalizeLinuxOrphanPath(
				path,
			)

		if !filepath.IsAbs(
			path,
		) {
			continue
		}

		if !suspiciousLinuxOrphan(
			entry,
			path,
		) {
			continue
		}

		_, err :=
			os.Stat(
				path,
			)

		if err == nil {
			continue
		}

		if !os.IsNotExist(
			err,
		) {
			continue
		}

		if _, exists :=
			groups[path]; !exists {

			order =
				append(
					order,
					path,
				)
		}

		groups[path] =
			append(
				groups[path],
				entry,
			)
	}

	nextID :=
		nextTargetID(
			targets,
		)

	for _, path := range order {

		entries :=
			groups[path]

		confidence :=
			"low"

		if len(entries) > 1 {
			confidence =
				"medium"
		}

		targets =
			append(
				targets,
				knowledge.Target{
					ID: nextID,

					Process: knowledge.Process{
						Name: filepath.Base(
							path,
						),

						Path: path,
					},

					Persistence: entries,

					Findings: []knowledge.Finding{
						{
							Type: "orphaned_persistence",

							Reason: "persistence references an executable that does not exist",
						},
					},

					Confidence: confidence,
				},
			)

		nextID++
	}

	return targets
}

func suspiciousLinuxOrphan(
	entry knowledge.Persistence,
	path string,
) bool {
	path =
		normalizeLinuxOrphanPath(
			path,
		)

	location :=
		strings.TrimSpace(
			entry.Location,
		)

	userPersistence :=
		[]string{
			"/.config/autostart/",
			"/.config/systemd/user/",
			"/.local/share/systemd/user/",
		}

	for _, value := range userPersistence {
		if strings.Contains(
			location,
			value,
		) {
			return true
		}
	}

	if shared.SuspiciousPath(
		path,
	) {
		return true
	}

	orphanOnlyLocations :=
		[]string{
			"/.config/",
			"/.local/bin/",
		}

	lower :=
		strings.ToLower(
			path,
		)

	for _, value := range orphanOnlyLocations {
		if strings.Contains(
			lower,
			value,
		) {
			return true
		}
	}

	return false
}

func linuxPersistenceExecutable(
	entry knowledge.Persistence,
) (
	string,
	bool,
) {
	switch entry.Type {
	case "autostart":
		path :=
			firstLinuxCommandToken(
				os.ExpandEnv(
					entry.Value,
				),
			)

		return path,
			path != ""

	case "service",
		"timer":

		path :=
			systemdExecutablePath(
				entry.Value,
			)

		return path,
			path != ""

	default:
		return "", false
	}
}

func systemdExecutablePath(
	value string,
) string {
	index :=
		strings.Index(
			value,
			"path=",
		)

	if index < 0 {
		return ""
	}

	value =
		value[index+len(
			"path=",
		):]

	if end :=
		strings.Index(
			value,
			" ;",
		); end >= 0 {

		value =
			value[:end]
	}

	return strings.Trim(
		strings.TrimSpace(
			value,
		),
		`"'`,
	)
}

func firstLinuxCommandToken(
	value string,
) string {
	value =
		strings.TrimSpace(
			value,
		)

	if value == "" {
		return ""
	}

	if value[0] == '"' ||
		value[0] == '\'' {

		quote :=
			value[0]

		if end :=
			strings.IndexByte(
				value[1:],
				quote,
			); end >= 0 {

			return value[1 : end+1]
		}
	}

	fields :=
		strings.Fields(
			value,
		)

	if len(fields) == 0 {
		return ""
	}

	return strings.Trim(
		fields[0],
		`"'`,
	)
}

func normalizeLinuxOrphanPath(
	path string,
) string {
	path =
		strings.TrimSpace(
			path,
		)

	path =
		strings.Trim(
			path,
			`"'`,
		)

	return strings.TrimSuffix(
		path,
		" (deleted)",
	)
}

func usedPersistence(
	targets []knowledge.Target,
) map[string]struct{} {
	used :=
		make(
			map[string]struct{},
		)

	for _, target := range targets {

		for _, entry := range target.Persistence {

			used[persistenceKey(
				entry,
			)] =
				struct{}{}
		}
	}

	return used
}

func persistenceKey(
	entry knowledge.Persistence,
) string {
	return entry.Type +
		"\x00" +
		entry.Location +
		"\x00" +
		entry.Name +
		"\x00" +
		entry.Value
}

func nextTargetID(
	targets []knowledge.Target,
) int {
	next :=
		1

	for _, target := range targets {

		if target.ID >= next {
			next =
				target.ID + 1
		}
	}

	return next
}
