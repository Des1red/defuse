//go:build windows

package windows

import (
	"path/filepath"
	"strings"

	shared "defuse/internal/engines/shared"
	"defuse/internal/knowledge"
)

type windowsEvaluation struct {
	Target knowledge.Target
	Score  int
}

func Correlate(
	processes []knowledge.Process,
	connections []knowledge.Connection,
	persistence []knowledge.Persistence,
) []knowledge.Target {
	var evaluations []windowsEvaluation

	for _, process := range processes {
		evaluations =
			append(
				evaluations,
				evaluateWindowsProcess(
					process,
					processes,
					connections,
					persistence,
				),
			)
	}

	targets :=
		clusterWindowsEvaluations(
			evaluations,
		)

	targets =
		appendOrphanPersistenceTargets(
			targets,
			persistence,
		)

	for index := range targets {

		targets[index].IPAddresses =
			shared.IPIndicators(
				targets[index],
			)
	}

	return targets
}

func evaluateWindowsProcess(
	process knowledge.Process,
	processes []knowledge.Process,
	connections []knowledge.Connection,
	persistence []knowledge.Persistence,
) windowsEvaluation {
	score := 0

	var findings []knowledge.Finding

	relatedProcesses :=
		shared.RelatedProcesses(
			process.PID,
			processes,
		)

	processConnections :=
		shared.ProcessConnections(
			process.PID,
			connections,
		)

	relatedConnections :=
		shared.RelatedConnections(
			relatedProcesses,
			connections,
		)

	processConnections =
		append(
			processConnections,
			relatedConnections...,
		)

	processPersistence :=
		matchingPersistence(
			process,
			persistence,
		)

	if len(processPersistence) > 0 {
		score += 2

		findings =
			append(
				findings,
				knowledge.Finding{
					Type: "persistence",

					Reason: "persistence mechanism references the running process",
				},
			)
	}

	if shared.HasPublicConnection(
		processConnections,
	) {
		score += 1

		findings =
			append(
				findings,
				knowledge.Finding{
					Type: "network",

					Reason: "process has an external network connection",
				},
			)
	}

	if shared.SuspiciousPath(
		process.Path,
	) {
		score += 3

		findings =
			append(
				findings,
				knowledge.Finding{
					Type: "path",

					Reason: "process executes from a user-writable location",
				},
			)
	}

	if masqueradingWindowsProcess(
		process,
	) {
		score += 4

		findings =
			append(
				findings,
				knowledge.Finding{
					Type: "masquerade",

					Reason: "system-like process name executes from an unexpected location",
				},
			)
	}

	return windowsEvaluation{
		Target: knowledge.Target{
			Process: process,

			Connections: processConnections,

			Persistence: processPersistence,

			RelatedProcesses: relatedProcesses,

			Findings: findings,
		},

		Score: score,
	}
}

func clusterWindowsEvaluations(
	evaluations []windowsEvaluation,
) []knowledge.Target {
	var targets []knowledge.Target

	used :=
		make(
			[]bool,
			len(evaluations),
		)

	targetID := 1

	/*
		Persistence-backed processes are evaluated first.

		This allows the persistent executable to become the root
		of a malware cluster instead of one of its helpers becoming
		the primary target.
	*/
	for index := range evaluations {
		if used[index] ||
			len(evaluations[index].Target.Persistence) == 0 {

			continue
		}

		indices :=
			windowsClusterIndices(
				evaluations,
				index,
				used,
			)

		hasSuspiciousRelated :=
			clusterHasSuspiciousRelated(
				evaluations,
				indices,
				index,
			)

		if evaluations[index].Score < 4 &&
			!hasSuspiciousRelated {

			continue
		}

		target :=
			mergeWindowsCluster(
				evaluations,
				indices,
				index,
			)

		score :=
			evaluations[index].Score

		if hasSuspiciousRelated {
			score += 2

			target.Findings =
				appendFinding(
					target.Findings,
					knowledge.Finding{
						Type: "process_cluster",

						Reason: "related process activity also triggered suspicious behavior",
					},
				)
		}

		for _, clusterIndex := range indices {
			used[clusterIndex] = true
		}

		target.ID = targetID
		target.Confidence = confidence(score)

		targets =
			append(
				targets,
				target,
			)

		targetID++
	}

	/*
		Anything suspicious that was not absorbed into a
		persistence-backed cluster becomes its own target.
	*/
	for index := range evaluations {
		if used[index] ||
			evaluations[index].Score < 4 {

			continue
		}

		indices :=
			windowsClusterIndices(
				evaluations,
				index,
				used,
			)

		target :=
			mergeWindowsCluster(
				evaluations,
				indices,
				index,
			)

		score :=
			evaluations[index].Score

		if clusterHasSuspiciousRelated(
			evaluations,
			indices,
			index,
		) {
			score += 2

			target.Findings =
				appendFinding(
					target.Findings,
					knowledge.Finding{
						Type: "process_cluster",

						Reason: "related process activity also triggered suspicious behavior",
					},
				)
		}

		for _, clusterIndex := range indices {
			used[clusterIndex] = true
		}

		target.ID = targetID
		target.Confidence = confidence(score)

		targets =
			append(
				targets,
				target,
			)

		targetID++
	}

	return targets
}

func windowsClusterIndices(
	evaluations []windowsEvaluation,
	start int,
	used []bool,
) []int {
	indices :=
		[]int{
			start,
		}

	selected :=
		map[int]struct{}{
			start: {},
		}

	cluster :=
		evaluations[start].Target

	changed := true

	for changed {
		changed = false

		for index, evaluation := range evaluations {
			if used[index] {
				continue
			}

			if _, exists :=
				selected[index]; exists {

				continue
			}

			if !relevantWindowsEvaluation(
				evaluation,
			) {
				continue
			}

			if !sameWindowsExecutable(
				cluster.Process,
				evaluation.Target.Process,
			) &&
				!targetContainsPID(
					cluster,
					evaluation.Target.Process.PID,
				) &&
				!targetContainsPID(
					evaluation.Target,
					cluster.Process.PID,
				) &&
				!targetsOverlap(
					cluster,
					evaluation.Target,
				) {

				continue
			}

			selected[index] =
				struct{}{}

			indices =
				append(
					indices,
					index,
				)

			cluster =
				mergeWindowsTargets(
					cluster,
					evaluation.Target,
				)

			changed = true
		}
	}

	return indices
}

func relevantWindowsEvaluation(
	evaluation windowsEvaluation,
) bool {
	return evaluation.Score >= 4 ||
		len(evaluation.Target.Persistence) > 0
}

func clusterHasSuspiciousRelated(
	evaluations []windowsEvaluation,
	indices []int,
	root int,
) bool {
	for _, index := range indices {
		if index == root {
			continue
		}

		if evaluations[index].Score >= 4 {
			return true
		}
	}

	return false
}

func mergeWindowsCluster(
	evaluations []windowsEvaluation,
	indices []int,
	root int,
) knowledge.Target {
	target :=
		evaluations[root].Target

	for _, index := range indices {
		if index == root {
			continue
		}

		target =
			mergeWindowsTargets(
				target,
				evaluations[index].Target,
			)
	}

	return target
}

func mergeWindowsTargets(
	target knowledge.Target,
	other knowledge.Target,
) knowledge.Target {
	if other.Process.PID != target.Process.PID {
		target.RelatedProcesses =
			appendProcess(
				target.RelatedProcesses,
				other.Process,
			)
	}

	for _, process := range other.RelatedProcesses {
		if process.PID == target.Process.PID {
			continue
		}

		target.RelatedProcesses =
			appendProcess(
				target.RelatedProcesses,
				process,
			)
	}

	for _, connection := range other.Connections {
		target.Connections =
			appendConnection(
				target.Connections,
				connection,
			)
	}

	for _, persistence := range other.Persistence {
		target.Persistence =
			appendPersistence(
				target.Persistence,
				persistence,
			)
	}

	return target
}

func appendProcess(
	processes []knowledge.Process,
	process knowledge.Process,
) []knowledge.Process {
	for _, existing := range processes {
		if existing.PID == process.PID {
			return processes
		}
	}

	return append(
		processes,
		process,
	)
}

func appendConnection(
	connections []knowledge.Connection,
	connection knowledge.Connection,
) []knowledge.Connection {
	for _, existing := range connections {
		if existing.PID == connection.PID &&
			existing.LocalAddress == connection.LocalAddress &&
			existing.LocalPort == connection.LocalPort &&
			existing.RemoteAddress == connection.RemoteAddress &&
			existing.RemotePort == connection.RemotePort &&
			existing.State == connection.State {

			return connections
		}
	}

	return append(
		connections,
		connection,
	)
}

func appendPersistence(
	persistence []knowledge.Persistence,
	entry knowledge.Persistence,
) []knowledge.Persistence {
	for _, existing := range persistence {
		if existing.Type == entry.Type &&
			existing.Location == entry.Location &&
			existing.Name == entry.Name &&
			existing.Value == entry.Value {

			return persistence
		}
	}

	return append(
		persistence,
		entry,
	)
}

func appendFinding(
	findings []knowledge.Finding,
	finding knowledge.Finding,
) []knowledge.Finding {
	for _, existing := range findings {
		if existing.Type == finding.Type &&
			existing.Reason == finding.Reason {

			return findings
		}
	}

	return append(
		findings,
		finding,
	)
}

func targetContainsPID(
	target knowledge.Target,
	pid uint32,
) bool {
	if target.Process.PID == pid {
		return true
	}

	for _, process := range target.RelatedProcesses {
		if process.PID == pid {
			return true
		}
	}

	return false
}

func targetsOverlap(
	left knowledge.Target,
	right knowledge.Target,
) bool {
	if targetContainsPID(
		left,
		right.Process.PID,
	) ||
		targetContainsPID(
			right,
			left.Process.PID,
		) {

		return true
	}

	for _, process := range right.RelatedProcesses {
		if targetContainsPID(
			left,
			process.PID,
		) {
			return true
		}
	}

	return false
}

func sameWindowsExecutable(
	left knowledge.Process,
	right knowledge.Process,
) bool {
	leftPath :=
		normalizeWindows(
			left.Path,
		)

	rightPath :=
		normalizeWindows(
			right.Path,
		)

	return leftPath != "" &&
		rightPath != "" &&
		leftPath == rightPath
}

func matchingPersistence(
	process knowledge.Process,
	persistence []knowledge.Persistence,
) []knowledge.Persistence {
	var matches []knowledge.Persistence

	processPath :=
		normalizeWindows(
			process.Path,
		)

	processName :=
		strings.ToLower(
			strings.TrimSpace(
				process.Name,
			),
		)

	for _, entry := range persistence {
		value :=
			normalizeWindows(
				entry.Value,
			)

		if processPath != "" &&
			strings.Contains(
				value,
				processPath,
			) {

			matches =
				append(
					matches,
					entry,
				)

			continue
		}

		if processName != "" &&
			containsWindowsExecutable(
				value,
				processName,
			) {

			matches =
				append(
					matches,
					entry,
				)
		}
	}

	return matches
}

func containsWindowsExecutable(
	value string,
	name string,
) bool {
	fields :=
		strings.FieldsFunc(
			value,
			func(
				r rune,
			) bool {
				switch r {
				case ' ',
					'\t',
					'\r',
					'\n',
					'"',
					'\'',
					'=',
					',',
					';',
					'|',
					'(',
					')',
					'[',
					']',
					'{',
					'}':

					return true
				}

				return false
			},
		)

	for _, field := range fields {
		field =
			strings.ReplaceAll(
				field,
				"/",
				`\`,
			)

		base :=
			strings.ToLower(
				filepath.Base(
					field,
				),
			)

		if base == name {
			return true
		}
	}

	return false
}

func masqueradingWindowsProcess(
	process knowledge.Process,
) bool {
	name :=
		strings.ToLower(
			process.Name,
		)

	systemNames :=
		map[string]struct{}{
			"svchost.exe":  {},
			"lsass.exe":    {},
			"csrss.exe":    {},
			"winlogon.exe": {},
			"services.exe": {},
			"smss.exe":     {},
			"explorer.exe": {},
		}

	if _, exists :=
		systemNames[name]; !exists {

		return false
	}

	path :=
		normalizeWindows(
			process.Path,
		)

	if path == "" {
		return false
	}

	return !strings.Contains(
		path,
		`\windows\`,
	)
}

func normalizeWindows(
	value string,
) string {
	value =
		strings.TrimSpace(
			value,
		)

	value =
		strings.Trim(
			value,
			`"'`,
		)

	value =
		strings.ReplaceAll(
			value,
			"/",
			`\`,
		)

	return strings.ToLower(
		value,
	)
}

func confidence(
	score int,
) string {
	switch {
	case score >= 7:
		return "high"

	case score >= 5:
		return "medium"

	default:
		return "low"
	}
}
