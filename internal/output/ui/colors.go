package ui

import "strings"

const (
	Reset = "\033[0m"

	Bold = "\033[1m"

	Dim = "\033[2m"

	Red = "\033[31m"

	Green = "\033[32m"

	Yellow = "\033[33m"

	Blue = "\033[34m"

	Magenta = "\033[35m"

	Cyan = "\033[36m"

	White = "\033[37m"
)

var plain = strings.NewReplacer(
	Reset, "",
	Bold, "",
	Dim, "",
	Red, "",
	Green, "",
	Yellow, "",
	Blue, "",
	Magenta, "",
	Cyan, "",
	White, "",
)

func Color(
	value string,
	color string,
) string {
	return color +
		value +
		Reset
}

func Success(
	value string,
) string {
	return Color(
		value,
		Green,
	)
}

func Warning(
	value string,
) string {
	return Color(
		value,
		Yellow,
	)
}

func Danger(
	value string,
) string {
	return Color(
		value,
		Red,
	)
}

func Info(
	value string,
) string {
	return Color(
		value,
		Cyan,
	)
}

func Accent(
	value string,
) string {
	return Color(
		value,
		Magenta,
	)
}

func Label(
	value string,
) string {
	return Bold +
		White +
		value +
		Reset
}

func Muted(
	value string,
) string {
	return Dim +
		value +
		Reset
}

func Plain(
	value string,
) string {
	return plain.Replace(
		value,
	)
}
