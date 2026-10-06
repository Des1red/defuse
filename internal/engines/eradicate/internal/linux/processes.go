//go:build linux

package linux

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"defuse/internal/knowledge"
)

func processCluster(
	target knowledge.Target,
) []knowledge.Process {
	var processes []knowledge.Process

	seen :=
		make(
			map[uint32]struct{},
		)

	add :=
		func(
			process knowledge.Process,
		) {
			if process.PID == 0 {
				return
			}

			if process.PID ==
				uint32(
					os.Getpid(),
				) {

				return
			}

			if _, exists :=
				seen[process.PID]; exists {

				return
			}

			seen[process.PID] =
				struct{}{}

			processes =
				append(
					processes,
					process,
				)
		}

	add(
		target.Process,
	)

	for _, process := range target.RelatedProcesses {

		add(
			process,
		)
	}

	return processes
}

func validateCluster(
	processes []knowledge.Process,
	result *knowledge.EradicateResult,
) (
	[]knowledge.Process,
	bool,
) {
	var active []knowledge.Process

	valid := true

	for _, process := range processes {

		running,
			err :=
			validateProcess(
				process,
			)

		action :=
			knowledge.Action{
				Type: "validate",

				Target: processLabel(
					process,
				),

				Success: err == nil,
			}

		if err != nil {
			action.Error =
				err.Error()

			result.Errors =
				append(
					result.Errors,
					fmt.Sprintf(
						"%s: %v",
						processLabel(
							process,
						),
						err,
					),
				)

			valid =
				false
		}

		result.Actions =
			append(
				result.Actions,
				action,
			)

		if err == nil &&
			running {

			active =
				append(
					active,
					process,
				)
		}
	}

	return active, valid
}

func validateProcess(
	process knowledge.Process,
) (
	bool,
	error,
) {
	exe :=
		filepath.Join(
			"/proc",
			strconv.FormatUint(
				uint64(
					process.PID,
				),
				10,
			),
			"exe",
		)

	livePath, err :=
		os.Readlink(
			exe,
		)

	if err != nil {
		if os.IsNotExist(
			err,
		) {
			return false, nil
		}

		return false, err
	}

	expectedPath :=
		normalizeExecutablePath(
			process.Path,
		)

	livePath =
		normalizeExecutablePath(
			livePath,
		)

	if expectedPath != "" {
		if livePath !=
			expectedPath {

			return true,
				fmt.Errorf(
					"PID identity changed: expected %s, found %s",
					expectedPath,
					livePath,
				)
		}

		return true, nil
	}

	if process.Name == "" {
		return true,
			errors.New(
				"process identity cannot be validated",
			)
	}

	liveName, err :=
		processName(
			process.PID,
		)

	if err != nil {
		return true, err
	}

	if liveName !=
		process.Name {

		return true,
			fmt.Errorf(
				"PID identity changed: expected %s, found %s",
				process.Name,
				liveName,
			)
	}

	return true, nil
}

func processName(
	pid uint32,
) (
	string,
	error,
) {
	path :=
		filepath.Join(
			"/proc",
			strconv.FormatUint(
				uint64(
					pid,
				),
				10,
			),
			"comm",
		)

	data, err :=
		os.ReadFile(
			path,
		)

	if err != nil {
		return "", err
	}

	return strings.TrimSpace(
		string(
			data,
		),
	), nil
}

func freezeCluster(
	processes []knowledge.Process,
	result *knowledge.EradicateResult,
) {
	errs :=
		signalProcesses(
			processes,
			syscall.SIGSTOP,
		)

	for index, process := range processes {

		err :=
			errs[index]

		appendAction(
			result,
			"freeze",
			processLabel(
				process,
			),
			err,
		)
	}
}

func terminateCluster(
	processes []knowledge.Process,
	result *knowledge.EradicateResult,
) {
	errs :=
		signalProcesses(
			processes,
			syscall.SIGKILL,
		)

	for index, process := range processes {

		err :=
			errs[index]

		appendAction(
			result,
			"terminate",
			processLabel(
				process,
			),
			err,
		)
	}
}

func signalProcesses(
	processes []knowledge.Process,
	signal syscall.Signal,
) []error {
	errs :=
		make(
			[]error,
			len(
				processes,
			),
		)

	var wait sync.WaitGroup

	wait.Add(
		len(
			processes,
		),
	)

	for index, process := range processes {

		go func(
			index int,
			pid uint32,
		) {
			defer wait.Done()

			err :=
				syscall.Kill(
					int(
						pid,
					),
					signal,
				)

			if errors.Is(
				err,
				syscall.ESRCH,
			) {
				err =
					nil
			}

			errs[index] =
				err
		}(
			index,
			process.PID,
		)
	}

	wait.Wait()

	return errs
}

func discoverProcessesByPath(
	paths []string,
) []knowledge.Process {
	wanted :=
		make(
			map[string]struct{},
		)

	for _, path := range paths {

		wanted[normalizeExecutablePath(
			path,
		)] =
			struct{}{}
	}

	entries, err :=
		os.ReadDir(
			"/proc",
		)

	if err != nil {
		return nil
	}

	var processes []knowledge.Process

	for _, entry := range entries {

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

		if pid ==
			uint32(
				os.Getpid(),
			) {

			continue
		}

		path, err :=
			os.Readlink(
				filepath.Join(
					"/proc",
					entry.Name(),
					"exe",
				),
			)

		if err != nil {
			continue
		}

		path =
			normalizeExecutablePath(
				path,
			)

		if _, exists :=
			wanted[path]; !exists {

			continue
		}

		name, _ :=
			processName(
				pid,
			)

		processes =
			append(
				processes,
				knowledge.Process{
					PID: pid,

					Name: name,

					Path: path,
				},
			)
	}

	return processes
}
