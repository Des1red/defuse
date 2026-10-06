package output

import (
	eradicateoutput "defuse/internal/output/eradicate"
	inspectoutput "defuse/internal/output/inspect"
)

func Inspect() {
	inspectoutput.Print()
}

func Eradicate() {
	eradicateoutput.Print()
}
