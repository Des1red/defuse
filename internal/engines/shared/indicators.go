package shared

import (
	"io"
	"net"
	"os"
	"regexp"
	"strings"

	"defuse/internal/knowledge"
)

const maxExecutableIndicatorBytes = 32 * 1024 * 1024

var ipv4Pattern = regexp.MustCompile(
	`(?:\d{1,3}\.){3}\d{1,3}`,
)

func IPIndicators(
	target knowledge.Target,
) []string {
	var addresses []string

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

			ip :=
				net.ParseIP(
					value,
				)

			if ip == nil ||
				ip.IsUnspecified() {

				return
			}

			value =
				ip.String()

			if _, exists :=
				seen[value]; exists {

				return
			}

			seen[value] =
				struct{}{}

			addresses =
				append(
					addresses,
					value,
				)
		}

	extractText :=
		func(
			value string,
		) {
			for _, candidate := range ipv4Pattern.FindAllString(
				value,
				-1,
			) {

				add(
					candidate,
				)
			}
		}

	for _, connection := range target.Connections {

		add(
			connection.LocalAddress,
		)

		add(
			connection.RemoteAddress,
		)
	}

	extractText(
		target.Process.CommandLine,
	)

	for _, entry := range target.Persistence {

		extractText(
			entry.Value,
		)
	}

	for _, process := range target.RelatedProcesses {

		extractText(
			process.CommandLine,
		)
	}

	for _, value := range executableIPIndicators(
		target.Process.Path,
	) {

		add(
			value,
		)
	}

	for _, process := range target.RelatedProcesses {

		if !SuspiciousPath(
			process.Path,
		) {
			continue
		}

		for _, value := range executableIPIndicators(
			process.Path,
		) {

			add(
				value,
			)
		}
	}

	return addresses
}

func executableIPIndicators(
	path string,
) []string {
	path =
		strings.TrimSpace(
			path,
		)

	path =
		strings.Trim(
			path,
			`"'`,
		)

	path =
		strings.TrimSuffix(
			path,
			" (deleted)",
		)

	if path == "" {
		return nil
	}

	file,
		err :=
		os.Open(
			path,
		)

	if err != nil {
		return nil
	}

	defer file.Close()

	data,
		err :=
		io.ReadAll(
			io.LimitReader(
				file,
				maxExecutableIndicatorBytes,
			),
		)

	if err != nil {
		return nil
	}

	var addresses []string

	seen :=
		make(
			map[string]struct{},
		)

	addMatches :=
		func(
			value string,
		) {
			for _, candidate := range ipv4Pattern.FindAllString(
				value,
				-1,
			) {

				ip :=
					net.ParseIP(
						candidate,
					)

				if ip == nil {
					continue
				}

				value :=
					ip.String()

				if _, exists :=
					seen[value]; exists {

					continue
				}

				seen[value] =
					struct{}{}

				addresses =
					append(
						addresses,
						value,
					)
			}
		}

	addMatches(
		string(
			data,
		),
	)

	addMatches(
		utf16ASCII(
			data,
			0,
		),
	)

	addMatches(
		utf16ASCII(
			data,
			1,
		),
	)

	return addresses
}

func utf16ASCII(
	data []byte,
	offset int,
) string {
	var builder strings.Builder

	for index := offset; index+1 < len(data); index += 2 {

		low :=
			data[index]

		high :=
			data[index+1]

		if high == 0 &&
			low >= 32 &&
			low <= 126 {

			builder.WriteByte(
				low,
			)

			continue
		}

		builder.WriteByte(
			' ',
		)
	}

	return builder.String()
}
