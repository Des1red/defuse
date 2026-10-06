//go:build windows

package windows

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

	paths :=
		make(
			map[string]string,
		)

	var order []string

	for _, entry := range persistence {

		if _, exists :=
			used[persistenceKey(
				entry,
			)]; exists {

			continue
		}

		candidates :=
			windowsPersistenceExecutables(
				entry,
			)

		for _, path := range candidates {

			path =
				normalizeWindowsOrphanPath(
					path,
				)

			if path == "" ||
				!filepath.IsAbs(
					path,
				) {

				continue
			}

			if !suspiciousWindowsOrphan(
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

			key :=
				strings.ToLower(
					path,
				)

			if _, exists :=
				groups[key]; !exists {

				order =
					append(
						order,
						key,
					)

				paths[key] =
					path
			}

			groups[key] =
				append(
					groups[key],
					entry,
				)
		}
	}

	nextID :=
		nextTargetID(
			targets,
		)

	for _, key := range order {

		path :=
			paths[key]

		entries :=
			groups[key]

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

func suspiciousWindowsOrphan(
	entry knowledge.Persistence,
	path string,
) bool {
	path =
		normalizeWindowsOrphanPath(
			path,
		)

	location :=
		strings.ToLower(
			strings.TrimSpace(
				entry.Location,
			),
		)

	userPersistence :=
		[]string{
			`hkcu\`,
			`\appdata\`,
			`\startup`,
		}

	for _, value := range userPersistence {
		if strings.Contains(
			location,
			value,
		) {
			return true
		}
	}

	return shared.SuspiciousPath(
		path,
	)
}
func windowsPersistenceExecutables(
	entry knowledge.Persistence,
) []string {
	switch entry.Type {
	case "registry",
		"service",
		"image_hijack":

		path :=
			windowsCommandExecutable(
				entry.Value,
			)

		if path == "" {
			return nil
		}

		return []string{
			path,
		}

	case "scheduled_task":
		var paths []string

		for _, command := range strings.Split(
			entry.Value,
			"|",
		) {

			path :=
				windowsCommandExecutable(
					command,
				)

			if path != "" {
				paths =
					append(
						paths,
						path,
					)
			}
		}

		return paths

	case "winlogon":
		var paths []string

		for _, command := range strings.Split(
			entry.Value,
			",",
		) {

			path :=
				windowsCommandExecutable(
					command,
				)

			if path != "" {
				paths =
					append(
						paths,
						path,
					)
			}
		}

		return paths

	case "appinit":
		return windowsAppInitPaths(
			entry.Value,
		)

	/*
		The current startup collector stores the Startup-folder
		entry itself in Value.

		It does not yet resolve .lnk targets, so treating that
		Value as the launched executable would be incorrect.
	*/
	case "startup":
		return nil

	default:
		return nil
	}
}

func windowsCommandExecutable(
	value string,
) string {
	value =
		expandWindowsEnvironment(
			strings.TrimSpace(
				value,
			),
		)

	if value == "" {
		return ""
	}

	if value[0] == '"' {
		if end :=
			strings.Index(
				value[1:],
				`"`,
			); end >= 0 {

			return strings.TrimSpace(
				value[1 : end+1],
			)
		}
	}

	lower :=
		strings.ToLower(
			value,
		)

	extensions :=
		[]string{
			".exe",
			".com",
			".bat",
			".cmd",
		}

	end :=
		-1

	for _, extension := range extensions {

		index :=
			strings.Index(
				lower,
				extension,
			)

		if index < 0 {
			continue
		}

		index +=
			len(
				extension,
			)

		if end == -1 ||
			index < end {

			end =
				index
		}
	}

	if end > 0 {
		return strings.Trim(
			strings.TrimSpace(
				value[:end],
			),
			`"'`,
		)
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

func windowsAppInitPaths(
	value string,
) []string {
	value =
		expandWindowsEnvironment(
			value,
		)

	value =
		strings.NewReplacer(
			",",
			" ",
			";",
			" ",
		).Replace(
			value,
		)

	tokens :=
		quotedWindowsTokens(
			value,
		)

	var paths []string

	for _, token := range tokens {

		token =
			normalizeWindowsOrphanPath(
				token,
			)

		if filepath.IsAbs(
			token,
		) {
			paths =
				append(
					paths,
					token,
				)
		}
	}

	return paths
}

func quotedWindowsTokens(
	value string,
) []string {
	var tokens []string

	var builder strings.Builder

	var quote rune

	flush :=
		func() {
			token :=
				strings.TrimSpace(
					builder.String(),
				)

			if token != "" {
				tokens =
					append(
						tokens,
						token,
					)
			}

			builder.Reset()
		}

	for _, char := range value {

		switch {
		case quote != 0:
			if char == quote {
				quote =
					0

				continue
			}

			builder.WriteRune(
				char,
			)

		case char == '"' ||
			char == '\'':

			quote =
				char

		case char == ' ' ||
			char == '\t' ||
			char == '\r' ||
			char == '\n':

			flush()

		default:
			builder.WriteRune(
				char,
			)
		}
	}

	flush()

	return tokens
}

func expandWindowsEnvironment(
	value string,
) string {
	var builder strings.Builder

	for index := 0; index < len(value); {

		if value[index] != '%' {
			builder.WriteByte(
				value[index],
			)

			index++

			continue
		}

		end :=
			strings.IndexByte(
				value[index+1:],
				'%',
			)

		if end < 0 {
			builder.WriteByte(
				value[index],
			)

			index++

			continue
		}

		end +=
			index + 1

		name :=
			value[index+1 : end]

		expanded,
			exists :=
			os.LookupEnv(
				name,
			)

		if !exists {
			builder.WriteString(
				value[index : end+1],
			)

			index =
				end + 1

			continue
		}

		builder.WriteString(
			expanded,
		)

		index =
			end + 1
	}

	return builder.String()
}

func normalizeWindowsOrphanPath(
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

	return filepath.Clean(
		path,
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
