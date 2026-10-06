package models

type EngineState struct {
	Active   bool
	Complete bool
}

type EngineRegistry struct {
	Inspect   EngineState
	Eradicate EngineState
}

var Engines = EngineRegistry{
	Inspect: EngineState{
		Active: true,
	},
	Eradicate: EngineState{
		Active: false,
	},
}
