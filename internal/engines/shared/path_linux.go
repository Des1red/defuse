//go:build linux

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
			"/tmp/",
			"/var/tmp/",
			"/dev/shm/",
			"/run/user/",
			"/.cache/",
			"/.config/autostart/",
		}

	for _, location := range locations {
		if strings.Contains(
			path,
			location,
		) {
			return true
		}
	}

	userPath :=
		strings.Contains(
			path,
			"/home/",
		) ||
			strings.HasPrefix(
				path,
				"/root/",
			)

	if userPath {
		userLocations :=
			[]string{
				"/documents/",
				"/desktop/",
				"/downloads/",
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
	return strings.ToLower(
		strings.TrimSpace(
			path,
		),
	)
}
