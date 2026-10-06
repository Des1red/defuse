package ui

import (
	"fmt"
	"strings"
)

func Title(
	builder *strings.Builder,
	value string,
) {
	builder.WriteString(
		"\n",
	)

	builder.WriteString(
		Bold +
			Cyan +
			value +
			Reset,
	)

	builder.WriteString(
		"\n",
	)

	builder.WriteString(
		Cyan +
			strings.Repeat(
				"=",
				len(value),
			) +
			Reset,
	)

	builder.WriteString(
		"\n",
	)
}

func Section(
	builder *strings.Builder,
	value string,
) {
	builder.WriteString(
		"\n",
	)

	builder.WriteString(
		Bold +
			Blue +
			value +
			Reset,
	)

	builder.WriteString(
		"\n",
	)

	builder.WriteString(
		Blue +
			strings.Repeat(
				"-",
				len(value),
			) +
			Reset,
	)

	builder.WriteString(
		"\n",
	)
}

func TreeNode(
	builder *strings.Builder,
	prefix string,
	last bool,
	value string,
) {
	branch :=
		"├─ "

	if last {
		branch =
			"└─ "
	}

	builder.WriteString(
		prefix,
	)

	builder.WriteString(
		Info(
			branch,
		),
	)

	builder.WriteString(
		value,
	)

	builder.WriteString(
		"\n",
	)
}

func TreeField(
	builder *strings.Builder,
	prefix string,
	last bool,
	label string,
	value string,
) {
	TreeNode(
		builder,
		prefix,
		last,
		Label(
			label,
		)+": "+
			value,
	)
}

func ChildPrefix(
	prefix string,
	last bool,
) string {
	if last {
		return prefix +
			"   "
	}

	return prefix +
		"│  "
}

func Field(
	builder *strings.Builder,
	label string,
	value string,
) {
	builder.WriteString(
		fmt.Sprintf(
			"%-16s %s\n",
			label+":",
			value,
		),
	)
}

func IndentedField(
	builder *strings.Builder,
	label string,
	value string,
) {
	builder.WriteString(
		fmt.Sprintf(
			"  %-14s %s\n",
			label+":",
			value,
		),
	)
}

func Bullet(
	builder *strings.Builder,
	value string,
) {
	builder.WriteString(
		"  - ",
	)

	builder.WriteString(
		value,
	)

	builder.WriteString(
		"\n",
	)
}

func Blank(
	builder *strings.Builder,
) {
	builder.WriteString(
		"\n",
	)
}
