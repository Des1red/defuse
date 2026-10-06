package shared

import (
	"net"

	"defuse/internal/knowledge"
)

func ProcessConnections(
	pid uint32,
	connections []knowledge.Connection,
) []knowledge.Connection {
	var result []knowledge.Connection

	for _, connection := range connections {

		if connection.PID != pid {
			continue
		}

		result =
			append(
				result,
				connection,
			)
	}

	return result
}

func HasPublicConnection(
	connections []knowledge.Connection,
) bool {
	for _, connection := range connections {

		if PublicAddress(
			connection.RemoteAddress,
		) {
			return true
		}
	}

	return false
}

func PublicAddress(
	address string,
) bool {
	ip :=
		net.ParseIP(
			address,
		)

	if ip == nil {
		return false
	}

	if !ip.IsGlobalUnicast() {
		return false
	}

	if ip.IsPrivate() {
		return false
	}

	if ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() {

		return false
	}

	return true
}
