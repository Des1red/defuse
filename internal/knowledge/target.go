package knowledge

type Process struct {
	PID  uint32
	PPID uint32

	Name string
	Path string

	CommandLine string
}

type Connection struct {
	PID uint32

	LocalAddress string
	LocalPort    uint16

	RemoteAddress string
	RemotePort    uint16

	State string
}

type Persistence struct {
	Type string

	Location string
	Name     string
	Value    string
}

type Finding struct {
	Type   string
	Reason string
}

type Target struct {
	ID int

	Process Process

	Connections []Connection

	IPAddresses []string

	Persistence []Persistence

	RelatedProcesses []Process

	Findings []Finding

	Confidence string
}
