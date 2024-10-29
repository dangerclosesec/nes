package nes

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/dangerclosesec/nes/internal/metrics"
	"github.com/dangerclosesec/nes/internal/utils"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
)

// HealthCheck represents container health check configuration
type HealthCheck struct {
	Test     []string `yaml:"test" json:"test"`
	Interval string   `yaml:"interval" json:"interval"`
	Timeout  string   `yaml:"timeout" json:"timeout"`
	Retries  int      `yaml:"retries" json:"retries"`
}

func (m *Manager) StartContainer(name string, service Service) error {
	log.Printf("Starting container %s\n", name)
	// Additional validation
	if m.Client == nil {
		return fmt.Errorf("Docker client not initialized")
	}
	if service.Image == "" {
		return fmt.Errorf("image not specified for service %s", name)
	}

	// First, let's check if the container exists with more thorough inspection
	inspectFilters := filters.NewArgs(
		filters.Arg("name", name),
		filters.Arg("name", "/"+name),
	)

	existingContainers, err := m.Client.ContainerList(m.Ctx, container.ListOptions{
		All:     true,
		Filters: inspectFilters,
	})

	if err != nil {
		return fmt.Errorf("failed to check for existing containers: %v", err)
	}

	if len(existingContainers) > 0 {
		// Force remove any existing containers with this name
		for _, c := range existingContainers {
			containerID := c.ID
			log.Printf("Found existing container %s (%s), forcing cleanup...", name, containerID[:12])

			if err := m.forceCleanupContainerByID(containerID); err != nil {
				if !client.IsErrNotFound(err) {
					return fmt.Errorf("failed to force cleanup container %s: %v", containerID[:12], err)
				}
			}

			// Wait for cleanup to take effect
			time.Sleep(500 * time.Millisecond)
		}
	}

	// Additional wait after cleanup
	time.Sleep(1 * time.Second)

	// Pull image with retry logic
	for retries := 0; retries < 3; retries++ {
		filterArgs := filters.NewArgs()
		filterArgs.Add("reference", service.Image)
		// List images with the filter
		images, err := m.Client.ImageList(m.Ctx, image.ListOptions{
			Filters: filterArgs,
		})

		if len(images) > 0 && err == nil {
			break
		}

		reader, err := m.Client.ImagePull(m.Ctx, service.Image, image.PullOptions{})
		if err == nil {
			if _, err := io.Copy(io.Discard, reader); err != nil {
				return fmt.Errorf("failed to discard image pull output: %v", err)
			}
			reader.Close()
			break
		}
		if retries == 2 {
			return fmt.Errorf("failed to pull image %s after retries: %v", service.Image, err)
		}
		time.Sleep(time.Second * time.Duration(retries+1))
	}

	// Container configuration
	containerConfig := &container.Config{
		Image:      service.Image,
		Hostname:   name,               // Use service name as hostname
		Domainname: name + ".internal", // Add internal domain
	}

	// Host configuration with DNS settings
	hostConfig := &container.HostConfig{
		ExtraHosts: service.ExtraHosts,
	}

	// Set optional configurations
	if len(service.Command) > 0 {
		containerConfig.Cmd = service.Command
	}

	if service.Environment != nil {
		containerConfig.Env = utils.MapToEnvSlice(service.Environment)
	}

	// Configure ports if specified
	if len(service.Ports) > 0 {
		portBindings := nat.PortMap{}
		exposedPorts := nat.PortSet{}

		for _, portMapping := range service.Ports {
			hostPort, containerPort, err := utils.ParsePort(portMapping)
			if err != nil {
				return fmt.Errorf("invalid port mapping %s: %v", portMapping, err)
			}

			// Check if port is available
			if !utils.IsPortAvailable(hostPort) {
				// Try to find and remove container using this port
				containers, err := m.Client.ContainerList(m.Ctx, container.ListOptions{All: true})
				if err != nil {
					return fmt.Errorf("failed to list containers while checking ports: %v", err)
				}

				for _, c := range containers {
					for _, p := range c.Ports {
						if strconv.FormatUint(uint64(p.PublicPort), 10) == hostPort {
							log.Printf("Found container %s using port %s, removing it", c.ID[:12], hostPort)
							timeout := 10
							if err := m.Client.ContainerStop(m.Ctx, c.ID, container.StopOptions{
								Timeout: &timeout,
							}); err != nil {
								log.Printf("Error stopping container %s: %v", c.ID[:12], err)
							}
							if err := m.Client.ContainerRemove(m.Ctx, c.ID, container.RemoveOptions{
								Force: true,
							}); err != nil {
								log.Printf("Error removing container %s: %v", c.ID[:12], err)
							}
							time.Sleep(time.Second)
							break
						}
					}
				}

				// Check again after cleanup
				if !utils.IsPortAvailable(hostPort) {
					return fmt.Errorf("port %s is still in use after cleanup attempt", hostPort)
				}
			}

			port := nat.Port(containerPort)
			portBindings[port] = []nat.PortBinding{{HostPort: hostPort}}
			exposedPorts[port] = struct{}{}
		}

		containerConfig.ExposedPorts = exposedPorts
		hostConfig.PortBindings = portBindings
	}

	// Configure volumes and mounts
	var mounts []mount.Mount

	if len(service.Volumes) > 0 {
		for _, volumeMapping := range service.Volumes {
			src, dst, err := utils.ParseVolume(volumeMapping)
			if err != nil {
				return fmt.Errorf("invalid volume mapping %s: %v", volumeMapping, err)
			}
			mounts = append(mounts, mount.Mount{
				Type:   mount.TypeVolume,
				Source: src,
				Target: dst,
			})
		}
	}

	if m.SecretManager != nil && len(service.Secrets) > 0 {
		secretMounts, err := m.SecretManager.PrepareSecrets(service)
		if err != nil {
			return fmt.Errorf("failed to prepare secrets: %v", err)
		}
		mounts = append(mounts, secretMounts...)
	}

	if len(mounts) > 0 {
		hostConfig.Mounts = mounts
	}

	// Configure health check if specified
	if service.HealthCheck != nil {
		healthcheck, err := m.createHealthCheck(service.HealthCheck)
		if err != nil {
			return fmt.Errorf("invalid health check configuration: %v", err)
		}
		containerConfig.Healthcheck = healthcheck
	}

	// Configure restart policy
	hostConfig.RestartPolicy = container.RestartPolicy{Name: "no"}
	if service.RestartPolicy != "" {
		switch service.RestartPolicy {
		case "always":
			hostConfig.RestartPolicy = container.RestartPolicy{Name: "always"}
		case "unless-stopped":
			hostConfig.RestartPolicy = container.RestartPolicy{Name: "unless-stopped"}
		case "on-failure":
			hostConfig.RestartPolicy = container.RestartPolicy{Name: "on-failure"}
		}
	}

	// Configure network settings
	var networkConfig *network.NetworkingConfig
	if len(service.Networks) > 0 {
		endpointsConfig := make(map[string]*network.EndpointSettings)
		for _, netName := range service.Networks {
			// Get network details
			netInfo, err := m.Client.NetworkInspect(m.Ctx, netName, network.InspectOptions{})
			if err != nil {
				return fmt.Errorf("failed to inspect network %s: %v", netName, err)
			}

			// Configure endpoints with aliases
			endpointsConfig[netName] = &network.EndpointSettings{
				NetworkID: netInfo.ID,
				Aliases: []string{
					name,                                // Service name as primary alias
					fmt.Sprintf("%s.%s", name, netName), // network-scoped name
				},
			}
		}
		networkConfig = &network.NetworkingConfig{
			EndpointsConfig: endpointsConfig,
		}
	}

	// Configure resources if specified
	if service.Resources != nil {
		resources, err := m.parseResources(service.Resources)
		if err != nil {
			return fmt.Errorf("failed to parse resource limits for container %s: %v", name, err)
		}
		hostConfig.Resources = resources
	}

	// Create container with retries
	var resp container.CreateResponse
	for retries := 0; retries < 3; retries++ {
		resp, err = m.Client.ContainerCreate(
			m.Ctx,
			containerConfig,
			hostConfig,
			networkConfig,
			nil,
			name,
		)

		if err == nil {
			break
		}

		if strings.Contains(err.Error(), "Conflict") {
			// If we get a conflict, try forcing cleanup one more time
			log.Printf("Container name conflict on attempt %d, forcing cleanup...", retries+1)

			// Get the conflicting container ID from the error message
			conflictID := extractContainerIDFromError(err.Error())
			if conflictID != "" {
				if err := m.forceCleanupContainerByID(conflictID); err != nil {
					log.Printf("Warning: force cleanup of conflicting container failed: %v", err)
				}
			}

			time.Sleep(time.Second * time.Duration(retries+1))
			continue
		}

		return fmt.Errorf("failed to create container on attempt %d: %v", retries+1, err)
	}

	// Start container
	if err := m.Client.ContainerStart(m.Ctx, resp.ID, container.StartOptions{}); err != nil {
		// If start fails, clean up the container we just created
		if cleanupErr := m.forceCleanupContainerByID(resp.ID); cleanupErr != nil {
			log.Printf("Warning: failed to cleanup container after failed start: %v", cleanupErr)
		}
		return fmt.Errorf("failed to start container: %v", err)
	}

	// Wait for networks to be ready
	if len(service.Networks) > 0 {
		for _, netName := range service.Networks {
			deadline := time.Now().Add(30 * time.Second)
			for time.Now().Before(deadline) {
				container, err := m.Client.ContainerInspect(m.Ctx, resp.ID)
				if err != nil {
					continue
				}

				if network, exists := container.NetworkSettings.Networks[netName]; exists {
					log.Printf("Container %s connected to network %s with IP %s",
						name, netName, network.IPAddress)
					break
				}

				time.Sleep(time.Second)
			}
		}
	}

	// Start log collection
	if m.LogFile != nil {
		m.Wg.Add(1)
		go m.collectLogs(resp.ID, name)
	}

	// Start log collection
	if m.StreamLogs {
		m.Wg.Add(1)
		go m.streamLogs(resp.ID, name)
	}

	// // Update container health status
	m.Mu.Lock()
	// if m.health != nil {
	// 	m.health.ActiveContainers[name] = true
	// }
	metrics.ServiceContainerCount.WithLabelValues(service.Hostname, name).Inc()
	m.Mu.Unlock()

	log.Printf("Successfully started container %s (%s)", name, resp.ID[:12])
	return nil
}

func (m *Manager) forceCleanupContainerByID(containerID string) error {
	// Try multiple methods to ensure container is removed
	methods := []struct {
		name string
		fn   func() error
	}{
		{"kill", func() error {
			return m.Client.ContainerKill(m.Ctx, containerID, "SIGKILL")
		}},
		{"stop", func() error {
			timeout := 1
			return m.Client.ContainerStop(m.Ctx, containerID, container.StopOptions{
				Timeout: &timeout,
			})
		}},
		{"remove", func() error {
			return m.Client.ContainerRemove(m.Ctx, containerID, container.RemoveOptions{
				Force:         true,
				RemoveVolumes: true,
			})
		}},
	}

	for _, method := range methods {
		if err := method.fn(); err != nil {
			log.Printf("Warning: %s failed for container %s: %v", method.name, containerID[:12], err)
		}
		time.Sleep(200 * time.Millisecond)
	}

	// Verify removal
	_, err := m.Client.ContainerInspect(m.Ctx, containerID)
	return err
}

// Helper to extract container ID from Docker error message
func extractContainerIDFromError(errMsg string) string {
	// Error message format: "Conflict. The container name "/name" is already in use by container "ID". You have to remove (or rename) that container to be able to reuse that name."
	parts := strings.Split(errMsg, `"`)
	if len(parts) >= 4 {
		return parts[3]
	}
	return ""
}

func (m *Manager) createHealthCheck(hc *HealthCheck) (*container.HealthConfig, error) {
	if hc == nil {
		return nil, nil
	}

	interval, err := time.ParseDuration(hc.Interval)
	if err != nil {
		return nil, fmt.Errorf("invalid healthcheck interval: %v", err)
	}

	timeout, err := time.ParseDuration(hc.Timeout)
	if err != nil {
		return nil, fmt.Errorf("invalid healthcheck timeout: %v", err)
	}

	return &container.HealthConfig{
		Test:     hc.Test,
		Interval: interval,
		Timeout:  timeout,
		Retries:  hc.Retries,
	}, nil
}

func (m *Manager) waitForHealthy(containerName string) error {
	log.Printf("Waiting for %s to be healthy\n", containerName)

	timeout := time.After(1 * time.Minute)
	tick := time.Tick(1 * time.Second)

	for {
		select {
		case <-timeout:
			return fmt.Errorf("timeout waiting for container %s to be healthy", containerName)
		case <-tick:
			container, err := m.Client.ContainerInspect(m.Ctx, containerName)
			if err != nil {
				continue
			}
			if container.State.Health != nil && container.State.Health.Status == "healthy" {
				log.Printf("Container %s is healthy\n", containerName)
				return nil
			}
		}
	}
}
