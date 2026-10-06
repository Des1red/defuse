//go:build windows

package windows

import (
	"fmt"

	"defuse/internal/knowledge"

	"golang.org/x/sys/windows/registry"
)

type registryLocation struct {
	Root registry.Key

	Hive string
	Path string

	View     uint32
	ViewName string
}

func registryPersistence() []knowledge.Persistence {
	var persistence []knowledge.Persistence

	locations :=
		[]registryLocation{
			{
				Root: registry.CURRENT_USER,

				Hive: "HKCU",

				Path: `Software\Microsoft\Windows\CurrentVersion\Run`,

				View: registry.WOW64_64KEY,

				ViewName: "64-bit",
			},
			{
				Root: registry.CURRENT_USER,

				Hive: "HKCU",

				Path: `Software\Microsoft\Windows\CurrentVersion\RunOnce`,

				View: registry.WOW64_64KEY,

				ViewName: "64-bit",
			},
			{
				Root: registry.LOCAL_MACHINE,

				Hive: "HKLM",

				Path: `Software\Microsoft\Windows\CurrentVersion\Run`,

				View: registry.WOW64_64KEY,

				ViewName: "64-bit",
			},
			{
				Root: registry.LOCAL_MACHINE,

				Hive: "HKLM",

				Path: `Software\Microsoft\Windows\CurrentVersion\RunOnce`,

				View: registry.WOW64_64KEY,

				ViewName: "64-bit",
			},

			{
				Root: registry.CURRENT_USER,

				Hive: "HKCU",

				Path: `Software\Microsoft\Windows\CurrentVersion\Run`,

				View: registry.WOW64_32KEY,

				ViewName: "32-bit",
			},
			{
				Root: registry.CURRENT_USER,

				Hive: "HKCU",

				Path: `Software\Microsoft\Windows\CurrentVersion\RunOnce`,

				View: registry.WOW64_32KEY,

				ViewName: "32-bit",
			},
			{
				Root: registry.LOCAL_MACHINE,

				Hive: "HKLM",

				Path: `Software\Microsoft\Windows\CurrentVersion\Run`,

				View: registry.WOW64_32KEY,

				ViewName: "32-bit",
			},
			{
				Root: registry.LOCAL_MACHINE,

				Hive: "HKLM",

				Path: `Software\Microsoft\Windows\CurrentVersion\RunOnce`,

				View: registry.WOW64_32KEY,

				ViewName: "32-bit",
			},
		}

	seen :=
		make(
			map[string]struct{},
		)

	for _, location := range locations {

		key, err :=
			registry.OpenKey(
				location.Root,
				location.Path,
				registry.QUERY_VALUE|
					location.View,
			)

		if err != nil {
			continue
		}

		names, err :=
			key.ReadValueNames(
				0,
			)

		if err != nil {
			key.Close()

			continue
		}

		for _, name := range names {

			value, _, err :=
				key.GetStringValue(
					name,
				)

			if err != nil {
				continue
			}

			registryPath :=
				fmt.Sprintf(
					"%s\\%s",
					location.Hive,
					location.Path,
				)

			id :=
				fmt.Sprintf(
					"%s|%s|%s",
					registryPath,
					name,
					value,
				)

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
						Type: "registry",

						Location: registryPath,

						Name: name,

						Value: value,
					},
				)
		}

		key.Close()
	}

	return persistence
}
