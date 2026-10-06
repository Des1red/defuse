//go:build windows

package shared

import "strings"

func SuspiciousPath(
	path string,
) bool {
	path =
		normalizePath(
			path,
		)

	locations :=
		[]string{
			`\appdata\local\temp\`,
			`\appdata\roaming\`,
			`\windows\temp\`,
			`\downloads\`,
			`\start menu\programs\startup\`,
			`\users\public\`,
		}

	for _, location := range locations {
		if strings.Contains(
			path,
			location,
		) {
			return true
		}
	}

	if strings.Contains(
		path,
		`\users\`,
	) {
		userLocations :=
			[]string{
				`\documents\`,
				`\desktop\`,
			}

		for _, location := range userLocations {
			if strings.Contains(
				path,
				location,
			) {
				return true
			}
		}
	}

	return false
}

func normalizePath(
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

	path =
		strings.ReplaceAll(
			path,
			"/",
			`\`,
		)

	return strings.ToLower(
		path,
	)
}
