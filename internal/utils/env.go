package utils

import "fmt"

// MapToEnvSlice converts a map of environment variables to a slice of strings
// in the format "key=value". This is useful for setting environment variables
// in contexts where a slice of strings is required.
//
// Parameters:
//   - envMap: A map where the keys are environment variable names and the values
//     are the corresponding environment variable values.
//
// Returns:
//   - A slice of strings where each string is in the format "key=value".
func MapToEnvSlice(envMap map[string]string) []string {
	var envSlice []string
	for k, v := range envMap {
		envSlice = append(envSlice, fmt.Sprintf("%s=%s", k, v))
	}
	return envSlice
}
