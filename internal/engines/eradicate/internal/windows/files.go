//go:build windows

package windows

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

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
			original :=
				cleanExecutablePath(
					path,
				)

			normalized :=
				normalizeExecutablePath(
					path,
				)

			if original == "" ||
				normalized == "" ||
				!filepath.IsAbs(
					original,
				) {

				return
			}

			if trustedSystemPath(
				original,
			) {
				return
			}

			if related &&
				!shared.SuspiciousPath(
					original,
				) {

				return
			}

			if _, exists :=
				seen[normalized]; exists {

				return
			}

			seen[normalized] =
				struct{}{}

			files =
				append(
					files,
					original,
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
	normalized :=
		normalizeExecutablePath(
			path,
		)

	if normalized == "" {
		return false
	}

	/*
		Windows Temp is intentionally excluded from the trusted
		Windows tree because execution from there is already treated
		as suspicious by Inspect.
	*/
	if strings.Contains(
		normalized,
		`\windows\temp\`,
	) {
		return false
	}

	roots :=
		[]string{
			os.Getenv(
				"SystemRoot",
			),

			os.Getenv(
				"ProgramFiles",
			),

			os.Getenv(
				"ProgramFiles(x86)",
			),
		}

	for _, root := range roots {
		root =
			normalizeExecutablePath(
				root,
			)

		if root == "" {
			continue
		}

		if normalized ==
			root ||
			strings.HasPrefix(
				normalized,
				root+`\`,
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
	path =
		cleanExecutablePath(
			path,
		)

	if strings.TrimSpace(
		path,
	) == "" {

		return errors.New(
			"file path is empty",
		)
	}

	var lastErr error

	for attempt := 0; attempt < 4; attempt++ {

		err :=
			os.Remove(
				path,
			)

		if err == nil ||
			os.IsNotExist(
				err,
			) {

			return nil
		}

		lastErr =
			err

		time.Sleep(
			50 * time.Millisecond,
		)
	}

	return lastErr
}

func cleanExecutablePath(
	path string,
) string {
	path =
		strings.TrimSpace(
			path,
		)

	path =
		strings.Trim(
			path,
			`"`,
		)

	if path == "" {
		return ""
	}

	return filepath.Clean(
		path,
	)
}

func normalizeExecutablePath(
	path string,
) string {
	path =
		cleanExecutablePath(
			path,
		)

	if path == "" {
		return ""
	}

	return strings.ToLower(
		path,
	)
}
