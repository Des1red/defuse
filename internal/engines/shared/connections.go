package shared

import (
	"defuse/internal/knowledge"

	gnet "github.com/shirou/gopsutil/v4/net"
)

func Connections() []knowledge.Connection {
	var connections []knowledge.Connection

	stats, err :=
		gnet.Connections(
			"inet",
		)

	if err != nil {
		return connections
	}

	for _, stat := range stats {

		if stat.Pid < 0 {
			continue
		}

		connection :=
			knowledge.Connection{
				PID: uint32(
					stat.Pid,
				),

				LocalAddress: stat.Laddr.IP,

				LocalPort: uint16(
					stat.Laddr.Port,
				),

				RemoteAddress: stat.Raddr.IP,

				RemotePort: uint16(
					stat.Raddr.Port,
				),

				State: stat.Status,
			}

		connections =
			append(
				connections,
				connection,
			)
	}

	return connections
}
