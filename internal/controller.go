package internal

import (
	"defuse/internal/engines/eradicate"
	"defuse/internal/engines/inspect"
	"defuse/internal/knowledge"
	"defuse/internal/models"
	"defuse/internal/output"
)

func Controller() {
	if models.Engines.Inspect.Active &&
		!models.Engines.Inspect.Complete {

		result :=
			inspect.Inspect()

		knowledge.Data.Inspect =
			result

		models.Engines.Inspect.Complete =
			true

		output.Inspect()
	}

	if models.Engines.Eradicate.Active &&
		!models.Engines.Eradicate.Complete {

		if knowledge.Data.Target == nil {
			return
		}

		result :=
			eradicate.Eradicate()

		knowledge.Data.Eradicate =
			result

		models.Engines.Eradicate.Complete =
			true

		output.Eradicate()
	}
}
