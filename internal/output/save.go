package output

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	eradicateoutput "defuse/internal/output/eradicate"
	inspectoutput "defuse/internal/output/inspect"
	"defuse/internal/output/ui"

	"defuse/internal/knowledge"
)

func Save() (
	string,
	error,
) {
	inspect :=
		hasInspectResults()

	eradicate :=
		hasEradicateResults()

	if !inspect &&
		!eradicate {

		return "", nil
	}

	var builder strings.Builder

	if inspect {
		builder.WriteString(
			inspectoutput.Render(),
		)
	}

	if eradicate {

		if builder.Len() > 0 {
			builder.WriteString(
				"\n",
			)
		}

		builder.WriteString(
			eradicateoutput.Render(),
		)
	}

	content :=
		ui.Plain(
			builder.String(),
		)

	err :=
		os.MkdirAll(
			"reports",
			0755,
		)

	if err != nil {
		return "", err
	}

	name :=
		"defuse-" +
			time.Now().Format(
				"20060102-150405",
			) +
			".txt"

	path :=
		filepath.Join(
			"reports",
			name,
		)

	err =
		os.WriteFile(
			path,
			[]byte(
				content,
			),
			0644,
		)

	if err != nil {
		return "", err
	}

	return path, nil
}

func hasInspectResults() bool {
	result :=
		knowledge.Data.Inspect

	return len(result.Processes) > 0 ||
		len(result.Connections) > 0 ||
		len(result.Persistence) > 0 ||
		len(result.Targets) > 0 ||
		len(result.Errors) > 0
}

func hasEradicateResults() bool {
	result :=
		knowledge.Data.Eradicate

	return len(result.Actions) > 0 ||
		result.Verified ||
		len(result.Errors) > 0
}
