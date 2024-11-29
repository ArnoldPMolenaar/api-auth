package utils

import "strconv"

// StringToUint function to convert string to uint.
func StringToUint(s string) (uint, error) {
	if u64, err := strconv.ParseUint(s, 10, 32); err != nil {
		return 0, err
	} else {
		return uint(u64), nil
	}
}
