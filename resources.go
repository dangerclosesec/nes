package nes

import (
	"fmt"

	"github.com/dangerclosesec/nes/internal/utils"
	"github.com/docker/docker/api/types/container"
)

type Resources struct {
	Limits struct {
		CPU    string `yaml:"cpu"`
		Memory string `yaml:"memory"`
	} `yaml:"limits"`
	Reservations struct {
		CPU    string `yaml:"cpu"`
		Memory string `yaml:"memory"`
	} `yaml:"reservations"`
}

func (m *Manager) parseResources(res *Resources) (container.Resources, error) {
	resources := container.Resources{}

	if res == nil {
		return resources, nil
	}

	// Parse CPU limits
	if res.Limits.CPU != "" {
		cpuLimit, err := utils.ParseCPU(res.Limits.CPU)
		if err != nil {
			return resources, fmt.Errorf("invalid CPU limit: %v", err)
		}
		resources.NanoCPUs = cpuLimit
	}

	// Parse CPU reservation/shares
	if res.Reservations.CPU != "" {
		cpuReservation, err := utils.ParseCPU(res.Reservations.CPU)
		if err != nil {
			return resources, fmt.Errorf("invalid CPU reservation: %v", err)
		}
		// Convert to CPU shares (1 CPU = 1024 shares)
		resources.CPUShares = (cpuReservation / 1_000_000_000) * 1024
	}

	// Parse memory limits
	if res.Limits.Memory != "" {
		memory := utils.ParseMemory(res.Limits.Memory)
		if memory < 0 {
			return resources, fmt.Errorf("invalid memory limit: %s", res.Limits.Memory)
		}
		resources.Memory = memory
	}

	// Parse memory reservations
	if res.Reservations.Memory != "" {
		memoryReservation := utils.ParseMemory(res.Reservations.Memory)
		if memoryReservation < 0 {
			return resources, fmt.Errorf("invalid memory reservation: %s", res.Reservations.Memory)
		}
		resources.MemoryReservation = memoryReservation
	}

	return resources, nil
}
