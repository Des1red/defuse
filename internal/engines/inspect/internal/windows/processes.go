//go:build windows

package windows

import (
	"unsafe"

	"defuse/internal/knowledge"

	"golang.org/x/sys/windows"
)

func Processes() []knowledge.Process {
	var processes []knowledge.Process

	snapshot, err :=
		windows.CreateToolhelp32Snapshot(
			windows.TH32CS_SNAPPROCESS,
			0,
		)

	if err != nil {
		return processes
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
		return processes
	}

	for {
		process :=
			knowledge.Process{
				PID: entry.ProcessID,

				PPID: entry.ParentProcessID,

				Name: windows.UTF16ToString(
					entry.ExeFile[:],
				),

				Path: processPath(
					entry.ProcessID,
				),
			}

		processes =
			append(
				processes,
				process,
			)

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

func processPath(
	pid uint32,
) string {
	handle, err :=
		windows.OpenProcess(
			windows.PROCESS_QUERY_LIMITED_INFORMATION,
			false,
			pid,
		)

	if err != nil {
		return ""
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
			len(buffer),
		)

	err =
		windows.QueryFullProcessImageName(
			handle,
			0,
			&buffer[0],
			&size,
		)

	if err != nil {
		return ""
	}

	return windows.UTF16ToString(
		buffer[:size],
	)
}
