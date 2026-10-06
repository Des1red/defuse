//go:build windows

package windows

import (
	"defuse/internal/knowledge"

	"golang.org/x/sys/windows/registry"
)

func imageHijackPersistence() []knowledge.Persistence {
	var persistence []knowledge.Persistence

	const basePath = `Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`

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

		base, err :=
			registry.OpenKey(
				registry.LOCAL_MACHINE,
				basePath,
				registry.ENUMERATE_SUB_KEYS|
					registry.QUERY_VALUE|
					view,
			)

		if err != nil {
			continue
		}

		names, err :=
			base.ReadSubKeyNames(
				0,
			)

		base.Close()

		if err != nil {
			continue
		}

		for _, name := range names {

			path :=
				basePath +
					`\` +
					name

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

			value, _, err :=
				key.GetStringValue(
					"Debugger",
				)

			key.Close()

			if err != nil ||
				value == "" {

				continue
			}

			id :=
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
						Type: "image_hijack",

						Location: `HKLM\` + path,

						Name: name,

						Value: value,
					},
				)
		}
	}

	return persistence
}
