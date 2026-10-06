//go:build windows

package windows

import (
	"defuse/internal/knowledge"

	"golang.org/x/sys/windows/registry"
)

func appInitPersistence() []knowledge.Persistence {
	var persistence []knowledge.Persistence

	const path = `Software\Microsoft\Windows NT\CurrentVersion\Windows`

	views :=
		[]uint32{
			registry.WOW64_64KEY,
			registry.WOW64_32KEY,
		}

	seen :=
		make(
			map[string]struct{},
		)

	for _, view := range views {

		key, err :=
			registry.OpenKey(
				registry.LOCAL_MACHINE,
				path,
				registry.QUERY_VALUE|
					view,
			)

		if err != nil {
			continue
		}

		enabled, _, err :=
			key.GetIntegerValue(
				"LoadAppInit_DLLs",
			)

		if err != nil ||
			enabled == 0 {

			key.Close()

			continue
		}

		value, _, err :=
			key.GetStringValue(
				"AppInit_DLLs",
			)

		key.Close()

		if err != nil ||
			value == "" {

			continue
		}

		if _, exists :=
			seen[value]; exists {

			continue
		}

		seen[value] =
			struct{}{}

		persistence =
			append(
				persistence,
				knowledge.Persistence{
					Type: "appinit",

					Location: `HKLM\` + path,

					Name: "AppInit_DLLs",

					Value: value,
				},
			)
	}

	return persistence
}
