package nes

import (
	"fmt"

	"github.com/docker/docker/api/types/volume"
)

// Volume represents volume configuration
type Volume struct {
	Driver string            `yaml:"driver" json:"driver"`
	Config map[string]string `yaml:"config,omitempty" json:"config"`
}

// setupVolumes sets up the volumes specified in the Manager's configuration.
// It checks if each volume already exists, and if not, creates it using the
// specified driver and configuration options.
//
// Parameters:
//   - m: A pointer to the Manager instance containing the volume configuration
//     and Docker client.
//
// Returns:
// - error: An error if any volume creation fails, otherwise nil.
func setupVolumes(m *Manager) error {
	for name, volConfig := range m.Config.Volumes {
		// Check if volume exists
		_, err := m.Client.VolumeInspect(m.Ctx, name)
		if err == nil {
			log.Printf("Volume %s exists, skipping", name)
			continue // Volume exists
		}

		// Create volume
		createOpts := volume.CreateOptions{
			Name:       name,
			Driver:     volConfig.Driver,
			DriverOpts: volConfig.Config,
		}
		_, err = m.Client.VolumeCreate(m.Ctx, createOpts)
		if err != nil {
			return fmt.Errorf("failed to create volume %s: %v", name, err)
		}
		log.Printf("Created volume: %s", name)
	}

	return nil
}
