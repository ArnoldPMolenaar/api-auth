package utils

import (
	"unicode"
)

// PascalCaseToCamelcase converts a PascalCase string to camelCase.
func PascalCaseToCamelcase(s string) string {
	if s == "" {
		return s
	}

	runes := []rune(s)
	runes[0] = unicode.ToLower(runes[0])

	return string(runes)
}
