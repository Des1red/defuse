//go:build linux

package linux

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"defuse/internal/knowledge"
)

func Processes() []knowledge.Process {
	var processes []knowledge.Process

	entries, err :=
		os.ReadDir(
			"/proc",
		)

	if err != nil {
		return processes
	}

	for _, entry := range entries {

		if !entry.IsDir() {
			continue
		}

		pid64, err :=
			strconv.ParseUint(
				entry.Name(),
				10,
				32,
			)

		if err != nil {
			continue
		}

		pid :=
			uint32(
				pid64,
			)

		process :=
			knowledge.Process{
				PID: pid,

				Name: processName(
					pid,
				),

				Path: processPath(
					pid,
				),

				CommandLine: processCommandLine(
					pid,
				),

				PPID: processParent(
					pid,
				),
			}

		processes =
			append(
				processes,
				process,
			)
	}

	return processes
}

func processName(
	pid uint32,
) string {
	path :=
		filepath.Join(
			"/proc",
			strconv.FormatUint(
				uint64(pid),
				10,
			),
			"comm",
		)

	data, err :=
		os.ReadFile(
			path,
		)

	if err != nil {
		return ""
	}

	return strings.TrimSpace(
		string(data),
	)
}

func processPath(
	pid uint32,
) string {
	path :=
		filepath.Join(
			"/proc",
			strconv.FormatUint(
				uint64(pid),
				10,
			),
			"exe",
		)

	target, err :=
		os.Readlink(
			path,
		)

	if err != nil {
		return ""
	}

	return target
}

func processCommandLine(
	pid uint32,
) string {
	path :=
		filepath.Join(
			"/proc",
			strconv.FormatUint(
				uint64(pid),
				10,
			),
			"cmdline",
		)

	data, err :=
		os.ReadFile(
			path,
		)

	if err != nil {
		return ""
	}

	command :=
		strings.ReplaceAll(
			string(data),
			"\x00",
			" ",
		)

	return strings.TrimSpace(
		command,
	)
}

func processParent(
	pid uint32,
) uint32 {
	path :=
		filepath.Join(
			"/proc",
			strconv.FormatUint(
				uint64(pid),
				10,
			),
			"status",
		)

	data, err :=
		os.ReadFile(
			path,
		)

	if err != nil {
		return 0
	}

	lines :=
		strings.Split(
			string(data),
			"\n",
		)

	for _, line := range lines {

		if !strings.HasPrefix(
			line,
			"PPid:",
		) {
			continue
		}

		fields :=
			strings.Fields(
				line,
			)

		if len(fields) != 2 {
			return 0
		}

		value, err :=
			strconv.ParseUint(
				fields[1],
				10,
				32,
			)

		if err != nil {
			return 0
		}

		return uint32(
			value,
		)
	}

	return 0
}
