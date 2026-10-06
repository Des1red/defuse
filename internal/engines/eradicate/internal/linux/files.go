//go:build linux

package linux

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"defuse/internal/engines/shared"
	"defuse/internal/knowledge"
)

func fileCandidates(
	target knowledge.Target,
) []string {
	var files []string

	seen :=
		make(
			map[string]struct{},
		)

	add :=
		func(
			path string,
			related bool,
		) {
			path =
				normalizeExecutablePath(
					path,
				)

			if path == "" ||
				!filepath.IsAbs(
					path,
				) {

				return
			}

			if trustedSystemPath(
				path,
			) {
				return
			}

			if related &&
				!shared.SuspiciousPath(
					path,
				) {

				return
			}
			if _, exists :=
				seen[path]; exists {

				return
			}

			seen[path] =
				struct{}{}

			files =
				append(
					files,
					path,
				)
		}

	add(
		target.Process.Path,
		false,
	)

	for _, process := range target.RelatedProcesses {

		add(
			process.Path,
			true,
		)
	}

	return files
}

func trustedSystemPath(
	path string,
) bool {
	prefixes :=
		[]string{
			"/usr/bin/",
			"/usr/sbin/",
			"/bin/",
			"/sbin/",
			"/usr/lib/",
			"/lib/",
			"/lib64/",
			"/boot/",
		}

	for _, prefix := range prefixes {

		if strings.HasPrefix(
			path,
			prefix,
		) {
			return true
		}
	}

	return false
}

func removeFiles(
	files []string,
	result *knowledge.EradicateResult,
) {
	for _, path := range files {

		err :=
			removeFile(
				path,
			)

		appendAction(
			result,
			"remove_file",
			path,
			err,
		)
	}
}

func removeFile(
	path string,
) error {
	if strings.TrimSpace(
		path,
	) == "" {

		return errors.New(
			"file path is empty",
		)
	}

	err :=
		os.Remove(
			path,
		)

	if os.IsNotExist(
		err,
	) {
		return nil
	}

	return err
}

func normalizeExecutablePath(
	path string,
) string {
	path =
		strings.TrimSpace(
			path,
		)

	return strings.TrimSuffix(
		path,
		" (deleted)",
	)
}
