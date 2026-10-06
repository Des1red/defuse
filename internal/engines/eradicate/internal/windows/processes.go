//go:build windows

package windows

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"defuse/internal/knowledge"

	"golang.org/x/sys/windows"
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

	valid :=
		true

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
	liveName,
		running,
		err :=
		liveProcessName(
			process.PID,
		)

	if err != nil {
		return false, err
	}

	if !running {
		return false, nil
	}

	expectedPath :=
		normalizeExecutablePath(
			process.Path,
		)

	if expectedPath != "" {
		livePath, err :=
			queryProcessPath(
				process.PID,
			)

		if err != nil {
			return true, err
		}

		livePath =
			normalizeExecutablePath(
				livePath,
			)

		if livePath !=
			expectedPath {

			return true,
				fmt.Errorf(
					"PID identity changed: expected %s, found %s",
					process.Path,
					livePath,
				)
		}

		return true, nil
	}

	if strings.TrimSpace(
		process.Name,
	) == "" {

		return true,
			errors.New(
				"process identity cannot be validated",
			)
	}

	if !strings.EqualFold(
		liveName,
		process.Name,
	) {

		return true,
			fmt.Errorf(
				"PID identity changed: expected %s, found %s",
				process.Name,
				liveName,
			)
	}

	return true, nil
}

func liveProcessName(
	pid uint32,
) (
	string,
	bool,
	error,
) {
	snapshot, err :=
		windows.CreateToolhelp32Snapshot(
			windows.TH32CS_SNAPPROCESS,
			0,
		)

	if err != nil {
		return "", false, err
	}

	defer windows.CloseHandle(
		snapshot,
	)

	var entry windows.ProcessEntry32

	entry.Size =
		uint32(
			unsafe.Sizeof(
				entry,
			),
		)

	err =
		windows.Process32First(
			snapshot,
			&entry,
		)

	if err != nil {
		return "", false, err
	}

	for {
		if entry.ProcessID ==
			pid {

			return windows.UTF16ToString(
					entry.ExeFile[:],
				),
				true,
				nil
		}

		err =
			windows.Process32Next(
				snapshot,
				&entry,
			)

		if err != nil {
			break
		}
	}

	return "", false, nil
}

func queryProcessPath(
	pid uint32,
) (
	string,
	error,
) {
	handle, err :=
		windows.OpenProcess(
			windows.PROCESS_QUERY_LIMITED_INFORMATION,
			false,
			pid,
		)

	if err != nil {
		return "", err
	}

	defer windows.CloseHandle(
		handle,
	)

	buffer :=
		make(
			[]uint16,
			32768,
		)

	size :=
		uint32(
			len(
				buffer,
			),
		)

	err =
		windows.QueryFullProcessImageName(
			handle,
			0,
			&buffer[0],
			&size,
		)

	if err != nil {
		return "", err
	}

	return windows.UTF16ToString(
		buffer[:size],
	), nil
}

func terminateCluster(
	processes []knowledge.Process,
	result *knowledge.EradicateResult,
) {
	for _, process := range processes {
		err :=
			terminateProcess(
				process.PID,
			)

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

func terminateProcess(
	pid uint32,
) error {
	if pid == 0 {
		return nil
	}

	handle, err :=
		windows.OpenProcess(
			windows.PROCESS_TERMINATE,
			false,
			pid,
		)

	if err != nil {
		_,
			running,
			checkErr :=
			liveProcessName(
				pid,
			)

		if checkErr == nil &&
			!running {

			return nil
		}

		return err
	}

	defer windows.CloseHandle(
		handle,
	)

	err =
		windows.TerminateProcess(
			handle,
			1,
		)

	if err != nil {
		_,
			running,
			checkErr :=
			liveProcessName(
				pid,
			)

		if checkErr == nil &&
			!running {

			return nil
		}

		return err
	}

	return nil
}

func discoverProcessesByPath(
	paths []string,
) []knowledge.Process {
	wanted :=
		make(
			map[string]struct{},
		)

	for _, path := range paths {
		path =
			normalizeExecutablePath(
				path,
			)

		if path == "" {
			continue
		}

		wanted[path] =
			struct{}{}
	}

	if len(wanted) == 0 {
		return nil
	}

	snapshot, err :=
		windows.CreateToolhelp32Snapshot(
			windows.TH32CS_SNAPPROCESS,
			0,
		)

	if err != nil {
		return nil
	}

	defer windows.CloseHandle(
		snapshot,
	)

	var entry windows.ProcessEntry32

	entry.Size =
		uint32(
			unsafe.Sizeof(
				entry,
			),
		)

	err =
		windows.Process32First(
			snapshot,
			&entry,
		)

	if err != nil {
		return nil
	}

	var processes []knowledge.Process

	for {
		pid :=
			entry.ProcessID

		if pid != 0 &&
			pid !=
				uint32(
					os.Getpid(),
				) {

			path, err :=
				queryProcessPath(
					pid,
				)

			if err == nil {
				normalized :=
					normalizeExecutablePath(
						path,
					)

				if _, exists :=
					wanted[normalized]; exists {

					processes =
						append(
							processes,
							knowledge.Process{
								PID: pid,

								PPID: entry.ParentProcessID,

								Name: windows.UTF16ToString(
									entry.ExeFile[:],
								),

								Path: path,
							},
						)
				}
			}
		}

		err =
			windows.Process32Next(
				snapshot,
				&entry,
			)

		if err != nil {
			break
		}
	}

	return processes
}
