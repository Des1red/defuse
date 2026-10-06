//go:build windows

package windows

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"defuse/internal/knowledge"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func removePersistence(
	target knowledge.Target,
	result *knowledge.EradicateResult,
) {
	for _, entry := range target.Persistence {
		err :=
			removePersistenceEntry(
				target,
				entry,
			)

		appendAction(
			result,
			"remove_persistence",
			persistenceLabel(
				entry,
			),
			err,
		)
	}
}

func removePersistenceEntry(
	target knowledge.Target,
	entry knowledge.Persistence,
) error {
	switch entry.Type {
	case "registry":
		return removeRegistryValue(
			entry.Location,
			entry.Name,
		)

	case "startup":
		return removeStartupEntry(
			entry,
		)

	case "service":
		return removeService(
			entry,
		)

	case "scheduled_task":
		return removeScheduledTask(
			entry,
		)

	case "winlogon":
		return removeWinlogon(
			target,
			entry,
		)

	case "appinit":
		return removeAppInit(
			target,
			entry,
		)

	case "image_hijack":
		return removeImageHijack(
			entry,
		)

	default:
		return fmt.Errorf(
			"unsupported persistence type %q",
			entry.Type,
		)
	}
}

func removeRegistryValue(
	location string,
	name string,
) error {
	root,
		path,
		err :=
		parseRegistryLocation(
			location,
		)

	if err != nil {
		return err
	}

	views :=
		[]uint32{
			registry.WOW64_64KEY,
			registry.WOW64_32KEY,
		}

	var firstErr error

	for _, view := range views {
		key, err :=
			registry.OpenKey(
				root,
				path,
				registry.SET_VALUE|
					view,
			)

		if err != nil {
			if errors.Is(
				err,
				registry.ErrNotExist,
			) {
				continue
			}

			if firstErr == nil {
				firstErr =
					err
			}

			continue
		}

		err =
			key.DeleteValue(
				name,
			)

		key.Close()

		if err != nil &&
			!errors.Is(
				err,
				registry.ErrNotExist,
			) {

			if firstErr == nil {
				firstErr =
					err
			}
		}
	}

	return firstErr
}

func removeStartupEntry(
	entry knowledge.Persistence,
) error {
	path :=
		strings.TrimSpace(
			entry.Value,
		)

	if path == "" {
		path =
			filepath.Join(
				entry.Location,
				entry.Name,
			)
	}

	return removeFile(
		path,
	)
}

func removeService(
	entry knowledge.Persistence,
) error {
	manager, err :=
		mgr.Connect()

	if err != nil {
		return err
	}

	defer manager.Disconnect()

	service, err :=
		manager.OpenService(
			entry.Name,
		)

	if err != nil {
		if errors.Is(
			err,
			windows.ERROR_SERVICE_DOES_NOT_EXIST,
		) {
			return nil
		}

		return err
	}

	defer service.Close()

	_,
		stopErr :=
		service.Control(
			svc.Stop,
		)

	if errors.Is(
		stopErr,
		windows.ERROR_SERVICE_NOT_ACTIVE,
	) {
		stopErr =
			nil
	}

	deleteErr :=
		service.Delete()

	if deleteErr != nil {
		if stopErr != nil {
			return fmt.Errorf(
				"stop failed: %v; delete failed: %v",
				stopErr,
				deleteErr,
			)
		}

		return deleteErr
	}

	return stopErr
}

func removeScheduledTask(
	entry knowledge.Persistence,
) error {
	name :=
		scheduledTaskName(
			entry,
		)

	if name == "" {
		return errors.New(
			"scheduled task name is empty",
		)
	}

	/*
		Query first.

		If the task is already absent, eradication is idempotent
		and there is nothing left to remove.
	*/
	err :=
		exec.Command(
			"schtasks.exe",
			"/Query",
			"/TN",
			name,
		).Run()

	if err != nil {
		return nil
	}

	output, err :=
		exec.Command(
			"schtasks.exe",
			"/Delete",
			"/TN",
			name,
			"/F",
		).CombinedOutput()

	if err != nil {
		message :=
			strings.TrimSpace(
				string(
					output,
				),
			)

		if message == "" {
			message =
				err.Error()
		}

		return errors.New(
			message,
		)
	}

	return nil
}

func removeWinlogon(
	target knowledge.Target,
	entry knowledge.Persistence,
) error {
	root,
		path,
		err :=
		parseRegistryLocation(
			entry.Location,
		)

	if err != nil {
		return err
	}

	references :=
		targetReferences(
			target,
		)

	views :=
		[]uint32{
			registry.WOW64_64KEY,
			registry.WOW64_32KEY,
		}

	var firstErr error

	for _, view := range views {
		key, err :=
			registry.OpenKey(
				root,
				path,
				registry.QUERY_VALUE|
					registry.SET_VALUE|
					view,
			)

		if err != nil {
			if errors.Is(
				err,
				registry.ErrNotExist,
			) {
				continue
			}

			if firstErr == nil {
				firstErr =
					err
			}

			continue
		}

		value, _, err :=
			key.GetStringValue(
				entry.Name,
			)

		if err != nil {
			key.Close()

			if errors.Is(
				err,
				registry.ErrNotExist,
			) {
				continue
			}

			if firstErr == nil {
				firstErr =
					err
			}

			continue
		}

		updated,
			changed :=
			stripTargetReferences(
				value,
				references,
			)

		if !changed {
			key.Close()

			continue
		}

		updated =
			cleanPersistenceValue(
				updated,
			)

		switch strings.ToLower(
			entry.Name,
		) {
		case "userinit":
			if updated == "" {
				updated =
					defaultUserinit()
			} else {
				updated =
					strings.TrimRight(
						updated,
						" ,",
					) +
						","
			}

		case "shell":
			if updated == "" {
				updated =
					"explorer.exe"
			}
		}

		err =
			key.SetStringValue(
				entry.Name,
				updated,
			)

		key.Close()

		if err != nil &&
			firstErr == nil {

			firstErr =
				err
		}
	}

	return firstErr
}

func removeAppInit(
	target knowledge.Target,
	entry knowledge.Persistence,
) error {
	root,
		path,
		err :=
		parseRegistryLocation(
			entry.Location,
		)

	if err != nil {
		return err
	}

	references :=
		targetReferences(
			target,
		)

	views :=
		[]uint32{
			registry.WOW64_64KEY,
			registry.WOW64_32KEY,
		}

	var firstErr error

	for _, view := range views {
		key, err :=
			registry.OpenKey(
				root,
				path,
				registry.QUERY_VALUE|
					registry.SET_VALUE|
					view,
			)

		if err != nil {
			if errors.Is(
				err,
				registry.ErrNotExist,
			) {
				continue
			}

			if firstErr == nil {
				firstErr =
					err
			}

			continue
		}

		value, _, err :=
			key.GetStringValue(
				"AppInit_DLLs",
			)

		if err != nil {
			key.Close()

			if errors.Is(
				err,
				registry.ErrNotExist,
			) {
				continue
			}

			if firstErr == nil {
				firstErr =
					err
			}

			continue
		}

		updated,
			changed :=
			stripTargetReferences(
				value,
				references,
			)

		if !changed {
			key.Close()

			continue
		}

		updated =
			cleanPersistenceValue(
				updated,
			)

		err =
			key.SetStringValue(
				"AppInit_DLLs",
				updated,
			)

		if err == nil &&
			updated == "" {

			err =
				key.SetDWordValue(
					"LoadAppInit_DLLs",
					0,
				)
		}

		key.Close()

		if err != nil &&
			firstErr == nil {

			firstErr =
				err
		}
	}

	return firstErr
}

func removeImageHijack(
	entry knowledge.Persistence,
) error {
	return removeRegistryValue(
		entry.Location,
		"Debugger",
	)
}

func parseRegistryLocation(
	location string,
) (
	registry.Key,
	string,
	error,
) {
	location =
		strings.TrimSpace(
			location,
		)

	location =
		strings.ReplaceAll(
			location,
			"/",
			`\`,
		)

	parts :=
		strings.SplitN(
			location,
			`\`,
			2,
		)

	if len(parts) != 2 ||
		strings.TrimSpace(
			parts[1],
		) == "" {

		return 0,
			"",
			fmt.Errorf(
				"invalid registry location %q",
				location,
			)
	}

	switch strings.ToUpper(
		parts[0],
	) {
	case "HKCU":
		return registry.CURRENT_USER,
			parts[1],
			nil

	case "HKLM":
		return registry.LOCAL_MACHINE,
			parts[1],
			nil

	default:
		return 0,
			"",
			fmt.Errorf(
				"unsupported registry hive %q",
				parts[0],
			)
	}
}

func scheduledTaskName(
	entry knowledge.Persistence,
) string {
	path :=
		strings.TrimSpace(
			entry.Location,
		)

	path =
		strings.TrimPrefix(
			path,
			"Task Scheduler",
		)

	path =
		strings.ReplaceAll(
			path,
			"/",
			`\`,
		)

	if path == "" {
		path =
			`\`
	}

	if !strings.HasPrefix(
		path,
		`\`,
	) {
		path =
			`\` +
				path
	}

	if !strings.HasSuffix(
		path,
		`\`,
	) {
		path +=
			`\`
	}

	return path +
		entry.Name
}

func targetReferences(
	target knowledge.Target,
) []string {
	var references []string

	seen :=
		make(
			map[string]struct{},
		)

	add :=
		func(
			value string,
		) {
			value =
				strings.TrimSpace(
					value,
				)

			value =
				strings.Trim(
					value,
					`"`,
				)

			if value == "" {
				return
			}

			key :=
				strings.ToLower(
					value,
				)

			if _, exists :=
				seen[key]; exists {

				return
			}

			seen[key] =
				struct{}{}

			references =
				append(
					references,
					value,
				)
		}

	if target.Process.Path != "" {
		add(
			target.Process.Path,
		)
	} else {
		add(
			target.Process.Name,
		)
	}

	for _, process := range target.RelatedProcesses {
		if process.Path != "" {
			add(
				process.Path,
			)
		}
	}

	return references
}

func stripTargetReferences(
	value string,
	references []string,
) (
	string,
	bool,
) {
	updated :=
		value

	changed :=
		false

	for _, reference := range references {
		if reference == "" {
			continue
		}

		var removed bool

		updated,
			removed =
			removeCaseInsensitive(
				updated,
				`"`+
					reference+
					`"`,
			)

		if removed {
			changed =
				true
		}

		updated,
			removed =
			removeCaseInsensitive(
				updated,
				reference,
			)

		if removed {
			changed =
				true
		}
	}

	return updated, changed
}

func removeCaseInsensitive(
	value string,
	target string,
) (
	string,
	bool,
) {
	if target == "" {
		return value, false
	}

	changed :=
		false

	for {
		lowerValue :=
			strings.ToLower(
				value,
			)

		lowerTarget :=
			strings.ToLower(
				target,
			)

		index :=
			strings.Index(
				lowerValue,
				lowerTarget,
			)

		if index < 0 {
			break
		}

		value =
			value[:index] +
				value[index+
					len(target):]

		changed =
			true
	}

	return value, changed
}

func cleanPersistenceValue(
	value string,
) string {
	value =
		strings.TrimSpace(
			value,
		)

	value =
		strings.ReplaceAll(
			value,
			`""`,
			"",
		)

	for strings.Contains(
		value,
		",,",
	) {
		value =
			strings.ReplaceAll(
				value,
				",,",
				",",
			)
	}

	return strings.Trim(
		value,
		" ,;\t",
	)
}

func defaultUserinit() string {
	root :=
		strings.TrimSpace(
			os.Getenv(
				"SystemRoot",
			),
		)

	if root == "" {
		root =
			`C:\Windows`
	}

	return filepath.Join(
		root,
		"System32",
		"userinit.exe",
	) +
		","
}
