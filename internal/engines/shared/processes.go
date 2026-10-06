package shared

import "defuse/internal/knowledge"

func RelatedProcesses(
	pid uint32,
	processes []knowledge.Process,
) []knowledge.Process {
	var related []knowledge.Process

	children :=
		make(
			map[uint32][]knowledge.Process,
		)

	for _, process := range processes {

		children[process.PPID] =
			append(
				children[process.PPID],
				process,
			)
	}

	queue :=
		[]uint32{
			pid,
		}

	visited :=
		map[uint32]struct{}{
			pid: {},
		}

	for len(queue) > 0 {
		parent :=
			queue[0]

		queue =
			queue[1:]

		for _, process := range children[parent] {

			if _, exists :=
				visited[process.PID]; exists {

				continue
			}

			visited[process.PID] =
				struct{}{}

			related =
				append(
					related,
					process,
				)

			queue =
				append(
					queue,
					process.PID,
				)
		}
	}

	return related
}

func RelatedConnections(
	processes []knowledge.Process,
	connections []knowledge.Connection,
) []knowledge.Connection {
	var related []knowledge.Connection

	pids :=
		make(
			map[uint32]struct{},
		)

	for _, process := range processes {

		pids[process.PID] =
			struct{}{}
	}

	for _, connection := range connections {

		if _, exists :=
			pids[connection.PID]; !exists {

			continue
		}

		related =
			append(
				related,
				connection,
			)
	}

	return related
}
