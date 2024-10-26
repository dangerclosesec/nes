package utils

import (
	"fmt"
	"net"
)

// IsPortAvailable checks if a given TCP port is available for use.
// It attempts to listen on the specified port and returns true if successful,
// indicating that the port is available. If an error occurs while trying to listen,
// it returns false, indicating that the port is already in use or unavailable.
//
// Parameters:
//   - port: A string representing the port number to check.
//
// Returns:
//   - bool: True if the port is available, false otherwise.
func IsPortAvailable(port string) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		return false
	}
	ln.Close()
	return true
}
