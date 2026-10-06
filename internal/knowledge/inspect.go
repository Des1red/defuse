package knowledge

type InspectResult struct {
	Processes []Process

	Connections []Connection

	Persistence []Persistence

	Targets []Target

	Errors []string
}
