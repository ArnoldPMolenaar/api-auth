package utils

import "strings"

// CamelcaseToPascalCase converts a camelCase string to PascalCase.
func CamelcaseToPascalCase(s string) string {
	if len(s) == 0 {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
