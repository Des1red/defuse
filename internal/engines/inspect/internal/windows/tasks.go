//go:build windows

package windows

import (
	"encoding/json"
	"os/exec"
	"strings"

	"defuse/internal/knowledge"
)

type scheduledTask struct {
	Name string `json:"Name"`

	Path string `json:"Path"`

	Actions string `json:"Actions"`
}

func scheduledPersistence() []knowledge.Persistence {
	var persistence []knowledge.Persistence

	script :=
		`
$tasks = @(
	Get-ScheduledTask |
	Where-Object {
		$_.State -ne "Disabled"
	} |
	ForEach-Object {
		$actions = @(
			$_.Actions |
			ForEach-Object {
				if ($_.Execute) {
					(
						$_.Execute + " " +
						$_.Arguments
					).Trim()
				}
			}
		)

		[PSCustomObject]@{
			Name    = $_.TaskName
			Path    = $_.TaskPath
			Actions = ($actions -join " | ")
		}
	}
)

ConvertTo-Json -InputObject $tasks -Compress
`

	command :=
		exec.Command(
			"powershell.exe",
			"-NoProfile",
			"-NonInteractive",
			"-Command",
			script,
		)

	output, err :=
		command.Output()

	if err != nil {
		return persistence
	}

	if strings.TrimSpace(
		string(output),
	) == "" {
		return persistence
	}

	var tasks []scheduledTask

	err =
		json.Unmarshal(
			output,
			&tasks,
		)

	if err != nil {
		return persistence
	}

	for _, task := range tasks {

		location :=
			"Task Scheduler" +
				task.Path

		persistence =
			append(
				persistence,
				knowledge.Persistence{
					Type: "scheduled_task",

					Location: location,

					Name: task.Name,

					Value: task.Actions,
				},
			)
	}

	return persistence
}
