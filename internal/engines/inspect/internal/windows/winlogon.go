//go:build windows

package windows

import (
	"defuse/internal/knowledge"

	"golang.org/x/sys/windows/registry"
)

func winlogonPersistence() []knowledge.Persistence {
	var persistence []knowledge.Persistence

	type location struct {
		root registry.Key

		hive string
		path string

		view uint32
	}

	locations :=
		[]location{
			{
				root: registry.LOCAL_MACHINE,

				hive: "HKLM",

				path: `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`,

				view: registry.WOW64_64KEY,
			},
			{
				root: registry.LOCAL_MACHINE,

				hive: "HKLM",

				path: `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`,

				view: registry.WOW64_32KEY,
			},
			{
				root: registry.CURRENT_USER,

				hive: "HKCU",

				path: `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`,

				view: registry.WOW64_64KEY,
			},
			{
				root: registry.CURRENT_USER,

				hive: "HKCU",

				path: `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`,

				view: registry.WOW64_32KEY,
			},
		}

	values :=
		[]string{
			"Shell",
			"Userinit",
		}

	seen :=
		make(
			map[string]struct{},
		)

	for _, location := range locations {

		key, err :=
			registry.OpenKey(
				location.root,
				location.path,
				registry.QUERY_VALUE|
					location.view,
			)

		if err != nil {
			continue
		}

		for _, name := range values {

			value, _, err :=
				key.GetStringValue(
					name,
				)

			if err != nil ||
				value == "" {

				continue
			}

			id :=
				location.hive +
					`\` +
					location.path +
					`|` +
					name +
					`|` +
					value

			if _, exists :=
				seen[id]; exists {

				continue
			}

			seen[id] =
				struct{}{}

			persistence =
				append(
					persistence,
					knowledge.Persistence{
						Type: "winlogon",

						Location: location.hive +
							`\` +
							location.path,

						Name: name,

						Value: value,
					},
				)
		}

		key.Close()
	}

	return persistence
}
