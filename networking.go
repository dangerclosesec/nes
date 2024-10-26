package nes

import (
	"fmt"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/network"
)

type Route struct {
	Service   string   `yaml:"service"`
	Port      int      `yaml:"port"`
	Protocols []string `yaml:"protocols,omitempty"`
}

type Network struct {
	Driver     string            `yaml:"driver"`
	Config     map[string]string `yaml:"config,omitempty"`
	IPAM       *NetworkIPAM      `yaml:"ipam,omitempty"`     // Add IPAM config
	Options    map[string]string `yaml:"options,omitempty"`  // Add network options
	Labels     map[string]string `yaml:"labels,omitempty"`   // Add network labels
	Internal   bool              `yaml:"internal,omitempty"` // Add internal network option
	EnableIPv6 bool              `yaml:"enable_ipv6,omitempty"`
}

// Add IPAM configuration types
type NetworkIPAM struct {
	Driver  string       `yaml:"driver,omitempty"`
	Config  []IPAMConfig `yaml:"config,omitempty"`
	Options interface{}  `yaml:"options,omitempty"`
}

type IPAMConfig struct {
	Subnet     string   `yaml:"subnet,omitempty"`
	Gateway    string   `yaml:"gateway,omitempty"`
	IPRange    string   `yaml:"ip_range,omitempty"`
	AuxAddress []string `yaml:"aux_address,omitempty"`
}

func (m *Manager) setupNetworks() error {
	// Get list of existing networks
	networks, err := m.Client.NetworkList(m.Ctx, network.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list networks: %v", err)
	}

	// Create a map of existing networks for easy lookup
	existingNetworks := make(map[string]network.Inspect)
	for _, network := range networks {
		existingNetworks[network.Name] = network
	}

	// Process each network in the configuration
	for name, netConfig := range m.Config.Networks {
		existingNetwork, exists := existingNetworks[name]
		shouldRecreate := false

		if exists {
			// Check if network configuration has changed
			if shouldRecreateNetwork(existingNetwork, netConfig) {
				log.Printf("Network %s configuration has changed, recreating...", name)
				shouldRecreate = true

				// Remove the network if it exists and needs to be recreated
				if err := removeNetwork(m, name); err != nil {
					return fmt.Errorf("failed to remove network %s: %v", name, err)
				}
			} else {
				log.Printf("Network %s configuration unchanged, skipping", name)
				continue
			}
		}

		// Create network if it doesn't exist or needs to be recreated
		if !exists || shouldRecreate {
			// Prepare network creation options
			netOptions := network.CreateOptions{
				Driver:     netConfig.Driver,
				Options:    netConfig.Options,
				Labels:     netConfig.Labels,
				Internal:   netConfig.Internal,
				EnableIPv6: &netConfig.EnableIPv6,
			}

			// Configure IPAM if specified
			if netConfig.IPAM != nil {
				ipamConfig := []network.IPAMConfig{}
				for _, conf := range netConfig.IPAM.Config {
					ipamConfig = append(ipamConfig, network.IPAMConfig{
						Subnet:     conf.Subnet,
						Gateway:    conf.Gateway,
						IPRange:    conf.IPRange,
						AuxAddress: make(map[string]string),
					})
				}

				// Convert IPAM options to map[string]string if they exist
				var ipamOptions map[string]string
				if netConfig.IPAM.Options != nil {
					if opts, ok := netConfig.IPAM.Options.(map[string]interface{}); ok {
						ipamOptions = make(map[string]string)
						for k, v := range opts {
							ipamOptions[k] = fmt.Sprintf("%v", v)
						}
					}
				}

				netOptions.IPAM = &network.IPAM{
					Driver:  netConfig.IPAM.Driver,
					Config:  ipamConfig,
					Options: ipamOptions,
				}
			}

			// Set default options for better DNS resolution
			if netOptions.Options == nil {
				netOptions.Options = make(map[string]string)
			}
			netOptions.Options["com.docker.network.bridge.enable_dns"] = "true"
			netOptions.Options["com.docker.network.bridge.enable_icc"] = "true"

			// Create the network with retry logic
			var createErr error
			for retries := 0; retries < 3; retries++ {
				if _, createErr = m.Client.NetworkCreate(m.Ctx, name, netOptions); createErr == nil {
					log.Printf("Created network: %s", name)
					break
				}
				time.Sleep(time.Second * time.Duration(retries+1))
			}
			if createErr != nil {
				return fmt.Errorf("failed to create network %s after retries: %v", name, createErr)
			}
		}
	}

	return nil
}

// shouldRecreateNetwork compares existing network configuration with desired configuration
func shouldRecreateNetwork(existing network.Inspect, desired Network) bool {
	// Check basic network properties
	if existing.Driver != desired.Driver ||
		existing.Internal != desired.Internal ||
		existing.EnableIPv6 != desired.EnableIPv6 {
		return true
	}

	// Check IPAM configuration
	if desired.IPAM != nil && len(desired.IPAM.Config) > 0 {
		if len(existing.IPAM.Config) == 0 {
			return true
		}

		// Compare IPAM configurations
		for i, desiredConfig := range desired.IPAM.Config {
			if i >= len(existing.IPAM.Config) {
				return true
			}

			existingConfig := existing.IPAM.Config[i]
			if existingConfig.Subnet != desiredConfig.Subnet ||
				existingConfig.Gateway != desiredConfig.Gateway ||
				existingConfig.IPRange != desiredConfig.IPRange {
				return true
			}
		}

		// Compare IPAM options if they exist
		if desired.IPAM.Options != nil {
			desiredOpts, ok := desired.IPAM.Options.(map[string]interface{})
			if ok {
				for k, v := range desiredOpts {
					if existingValue, exists := existing.IPAM.Options[k]; !exists ||
						fmt.Sprintf("%v", existingValue) != fmt.Sprintf("%v", v) {
						return true
					}
				}
			}
		}
	}

	// Check network options
	for key, value := range desired.Options {
		if existingValue, ok := existing.Options[key]; !ok || existingValue != value {
			return true
		}
	}

	return false
}

// removeNetwork removes a network with proper error handling and retries
func removeNetwork(m *Manager, name string) error {
	// List containers using this network
	containers, err := m.Client.ContainerList(m.Ctx, container.ListOptions{
		All:     true,
		Filters: filters.NewArgs(filters.Arg("network", name)),
	})
	if err != nil {
		return fmt.Errorf("failed to list containers on network %s: %v", name, err)
	}

	// Disconnect all containers from the network
	for _, container := range containers {
		log.Printf("Disconnecting container %s from network %s", container.ID[:12], name)
		if err := m.Client.NetworkDisconnect(m.Ctx, name, container.ID, true); err != nil {
			log.Printf("Warning: failed to disconnect container %s: %v", container.ID[:12], err)
		}
	}

	// Remove network with retries
	var lastErr error
	for retries := 0; retries < 3; retries++ {
		if err := m.Client.NetworkRemove(m.Ctx, name); err != nil {
			lastErr = err
			log.Printf("Retry %d: Failed to remove network %s: %v", retries+1, name, err)
			time.Sleep(time.Second * time.Duration(retries+1))
			continue
		}
		return nil
	}

	return fmt.Errorf("failed to remove network %s after retries: %v", name, lastErr)
}
