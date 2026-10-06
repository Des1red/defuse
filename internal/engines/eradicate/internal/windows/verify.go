//go:build windows

package windows

import (
	"errors"
	"os"
	"os/exec"
	"strings"

	"defuse/internal/knowledge"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"
)

func verify(
	cluster []knowledge.Process,
	persistence []knowledge.Persistence,
	files []string,
	target knowledge.Target,
) bool {
	for _, process := range cluster {
		running,
			err :=
			validateProcess(
				process,
			)

		if err != nil ||
			running {

			return false
		}
	}

	if len(
		discoverProcessesByPath(
			files,
		),
	) > 0 {

		return false
	}

	for _, entry := range persistence {
		if persistenceExists(
			entry,
			target,
		) {

			return false
		}
	}

	for _, path := range files {
		if _, err :=
			os.Lstat(
				path,
			); err == nil {

			return false
		}
	}

	return true
}

func persistenceExists(
	entry knowledge.Persistence,
	target knowledge.Target,
) bool {
	switch entry.Type {
	case "registry":
		return registryValueExists(
			entry.Location,
			entry.Name,
		)

	case "startup":
		path :=
			strings.TrimSpace(
				entry.Value,
			)

		if path == "" {
			path =
				entry.Location +
					`\` +
					entry.Name
		}

		_,
			err :=
			os.Lstat(
				path,
			)

		return err == nil

	case "service":
		return serviceExists(
			entry.Name,
		)

	case "scheduled_task":
		return scheduledTaskExists(
			entry,
		)

	case "winlogon":
		return registryReferenceExists(
			entry.Location,
			entry.Name,
			targetReferences(
				target,
			),
		)

	case "appinit":
		return registryReferenceExists(
			entry.Location,
			"AppInit_DLLs",
			targetReferences(
				target,
			),
		)

	case "image_hijack":
		return registryReferenceExists(
			entry.Location,
			"Debugger",
			targetReferences(
				target,
			),
		)

	default:
		return true
	}
}

func registryValueExists(
	location string,
	name string,
) bool {
	root,
		path,
		err :=
		parseRegistryLocation(
			location,
		)

	if err != nil {
		return true
	}

	views :=
		[]uint32{
			registry.WOW64_64KEY,
			registry.WOW64_32KEY,
		}

	for _, view := range views {
		key, err :=
			registry.OpenKey(
				root,
				path,
				registry.QUERY_VALUE|
					view,
			)

		if err != nil {
			continue
		}

		_,
			_,
			err =
			key.GetStringValue(
				name,
			)

		key.Close()

		if err == nil {
			return true
		}

		if !errors.Is(
			err,
			registry.ErrNotExist,
		) {
			return true
		}
	}

	return false
}

func registryReferenceExists(
	location string,
	name string,
	references []string,
) bool {
	root,
		path,
		err :=
		parseRegistryLocation(
			location,
		)

	if err != nil {
		return true
	}

	views :=
		[]uint32{
			registry.WOW64_64KEY,
			registry.WOW64_32KEY,
		}

	for _, view := range views {
		key, err :=
			registry.OpenKey(
				root,
				path,
				registry.QUERY_VALUE|
					view,
			)

		if err != nil {
			continue
		}

		value, _, err :=
			key.GetStringValue(
				name,
			)

		key.Close()

		if err != nil {
			continue
		}

		lower :=
			strings.ToLower(
				value,
			)

		for _, reference := range references {
			reference =
				strings.TrimSpace(
					reference,
				)

			if reference == "" {
				continue
			}

			if strings.Contains(
				lower,
				strings.ToLower(
					reference,
				),
			) {

				return true
			}
		}
	}

	return false
}

func serviceExists(
	name string,
) bool {
	manager, err :=
		mgr.Connect()

	if err != nil {
		return true
	}

	defer manager.Disconnect()

	service, err :=
		manager.OpenService(
			name,
		)

	if err != nil {
		if errors.Is(
			err,
			windows.ERROR_SERVICE_DOES_NOT_EXIST,
		) {
			return false
		}

		return true
	}

	service.Close()

	return true
}

func scheduledTaskExists(
	entry knowledge.Persistence,
) bool {
	name :=
		scheduledTaskName(
			entry,
		)

	if name == "" {
		return true
	}

	err :=
		exec.Command(
			"schtasks.exe",
			"/Query",
			"/TN",
			name,
		).Run()

	return err == nil
}
