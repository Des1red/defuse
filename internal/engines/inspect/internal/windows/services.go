//go:build windows

package windows

import (
	"defuse/internal/knowledge"

	"golang.org/x/sys/windows/svc/mgr"
)

func servicePersistence() []knowledge.Persistence {
	var persistence []knowledge.Persistence

	manager, err :=
		mgr.Connect()

	if err != nil {
		return persistence
	}

	defer manager.Disconnect()

	names, err :=
		manager.ListServices()

	if err != nil {
		return persistence
	}

	for _, name := range names {

		service, err :=
			manager.OpenService(
				name,
			)

		if err != nil {
			continue
		}

		config, err :=
			service.Config()

		service.Close()

		if err != nil {
			continue
		}

		if config.StartType !=
			mgr.StartAutomatic {

			continue
		}

		persistence =
			append(
				persistence,
				knowledge.Persistence{
					Type: "service",

					Location: "Windows Service Control Manager",

					Name: name,

					Value: config.BinaryPathName,
				},
			)
	}

	return persistence
}
