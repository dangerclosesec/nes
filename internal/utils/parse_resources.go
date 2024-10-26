// Package utils provides utility functions for parsing resource specifications
// such as CPU, memory, ports, and volumes.
package utils

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseCPU converts a CPU string representation to its equivalent in nanoCPU units.
// The function handles both millicpu (e.g., "500m") and direct CPU values (e.g., "0.5" or "2").
//
// Parameters:
//   - cpu: A string representing the CPU value.
//
// Returns:
//   - int64: The CPU value in nanoCPU units.
//   - error: An error if the CPU value is invalid or cannot be parsed.
//
// Examples:
//   - "500m" -> 500,000,000 nanoCPU
//   - "0.5" -> 500,000,000 nanoCPU
//   - "2" -> 2,000,000,000 nanoCPU
//
// Returns:
//
//	int64: The equivalent memory size in bytes, or -1 if the input is invalid or causes an overflow.
func ParseCPU(cpu string) (int64, error) {
	if cpu == "" {
		return 0, nil
	}

	cpu = strings.TrimSpace(cpu)

	// Handle millicpu format (e.g., "500m")
	if strings.HasSuffix(cpu, "m") {
		value, err := strconv.ParseFloat(cpu[:len(cpu)-1], 64)
		if err != nil {
			return 0, fmt.Errorf("invalid CPU value: %s", cpu)
		}
		// Convert millicpu to nanoCPU
		// 1000m = 1 CPU = 1_000_000_000 nanoCPU
		return int64(value * 1_000_000), nil
	}

	// Handle direct CPU value (e.g., "0.5" or "2")
	value, err := strconv.ParseFloat(cpu, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid CPU value: %s", cpu)
	}
	// Convert CPU units to nanoCPU
	return int64(value * 1_000_000_000), nil
}

// ParsePort parses a port mapping string in the format "hostPort:containerPort"
// and returns the host port, container port with "/tcp" appended, and an error if the format is invalid.
//
// Parameters:
//   - portMapping: A string representing the port mapping in the format "hostPort:containerPort".
//
// Returns:
//   - string: The host port.
//   - string: The container port with "/tcp" appended.
//   - error: An error if the port mapping format is invalid.
func ParsePort(portMapping string) (string, string, error) {
	parts := strings.Split(portMapping, ":")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid port mapping: %s", portMapping)
	}
	return parts[0], parts[1] + "/tcp", nil
}

// ParseVolume takes a volume mapping string in the format "source:destination"
// and splits it into the source and destination parts. It returns an error if
// the volume mapping is not in the correct format.
//
// Parameters:
//   - volumeMapping: A string representing the volume mapping in the format "source:destination".
//
// Returns:
//   - string: The source part of the volume mapping.
//   - string: The destination part of the volume mapping.
//   - error: An error if the volume mapping is invalid.
func ParseVolume(volumeMapping string) (string, string, error) {
	parts := strings.Split(volumeMapping, ":")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid volume mapping: %s", volumeMapping)
	}
	return parts[0], parts[1], nil
}

// ParseMemory converts a memory size string with units (e.g., "1G", "512M", "1024K")
// into its equivalent value in bytes as an int64. If the input string is empty, it returns 0.
// Supported units are "G" for gigabytes, "M" for megabytes, and "K" for kilobytes.
// If the input string has an invalid format or causes an overflow, it returns -1.
//
// Parameters:
//
//	memory (string): The memory size string to be parsed.
//
// Returns:
//
//	int64: The equivalent memory size in bytes, or -1 if the input is invalid or causes an overflow.
func ParseMemory(memory string) int64 {
	if memory == "" {
		return 0
	}

	memory = strings.ToLower(strings.TrimSpace(memory))
	multiplier := int64(1)

	if strings.HasSuffix(memory, "g") {
		multiplier = 1024 * 1024 * 1024
		memory = memory[:len(memory)-1]
	} else if strings.HasSuffix(memory, "m") {
		multiplier = 1024 * 1024
		memory = memory[:len(memory)-1]
	} else if strings.HasSuffix(memory, "k") {
		multiplier = 1024
		memory = memory[:len(memory)-1]
	}

	value, err := strconv.ParseInt(memory, 10, 64)
	if err != nil {
		return -1 // Indicate invalid memory value
	}

	result := value * multiplier
	if result < 0 {
		return -1 // Indicate overflow
	}

	return result
}

// ParseNanoCPU converts a CPU string representation to a float64 value.
// The input can be in millicores (e.g., "500m") or cores (e.g., "0.5").
// If the input is in millicores, it divides the value by 1000 to convert it to cores.
//
// Parameters:
// - cpu: A string representing the CPU value.
//
// Returns:
// - A float64 representing the CPU value in cores.
func ParseNanoCPU(cpu string) float64 {
	if strings.HasSuffix(cpu, "m") {
		value, _ := strconv.ParseFloat(cpu[:len(cpu)-1], 64)
		return value / 1000.0
	}
	value, _ := strconv.ParseFloat(cpu, 64)
	return value
}
