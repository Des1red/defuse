//go:build !windows && !linux

package inspect

func Inspect() Result {
	var result Result

	result.Errors =
		append(
			result.Errors,
			"Inspect is not implemented for this platform",
		)

	return result
}
