package nes

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

// ContainerResolver handles Docker container discovery and port mapping
type ContainerResolver struct {
	client        *client.Client
	containers    map[string]*ContainerInfo
	mu            sync.RWMutex
	updateTimeout time.Duration
	done          chan struct{}
}

// ContainerInfo stores container details and port mappings
type ContainerInfo struct {
	ID           string
	Name         string
	ServiceName  string
	PortMappings map[string]PortBinding // key: containerPort/protocol
	LastUpdated  time.Time
	Health       string
}

// PortBinding represents a port binding configuration
type PortBinding struct {
	HostIP   string
	HostPort string
	Protocol string
}

// NewContainerResolver creates a new container resolver
func NewContainerResolver(dockerClient *client.Client) *ContainerResolver {
	return &ContainerResolver{
		client:        dockerClient,
		containers:    make(map[string]*ContainerInfo),
		updateTimeout: 10 * time.Second,
		done:          make(chan struct{}),
	}
}

// Start begins the container discovery process
func (cr *ContainerResolver) Start() {
	go cr.discoveryLoop()
}

// Stop stops the container discovery process
func (cr *ContainerResolver) Stop() {
	close(cr.done)
}

func (cr *ContainerResolver) discoveryLoop() {
	ticker := time.NewTicker(cr.updateTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-cr.done:
			return
		case <-ticker.C:
			if err := cr.updateContainers(); err != nil {
				log.Printf("Error updating containers: %v", err)
			}
		}
	}
}

func (cr *ContainerResolver) updateContainers() error {
	containers, err := cr.client.ContainerList(context.Background(), container.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	cr.mu.Lock()
	defer cr.mu.Unlock()

	// Clear old container cache
	newContainers := make(map[string]*ContainerInfo)

	for _, container := range containers {
		// Get detailed container info
		inspect, err := cr.client.ContainerInspect(context.Background(), container.ID)
		if err != nil {
			log.Printf("Error inspecting container %s: %v", container.ID, err)
			continue
		}

		// Extract service name from labels or container name
		serviceName := cr.getServiceName(inspect)

		// Parse port mappings
		portMappings := make(map[string]PortBinding)
		for containerPort, bindings := range inspect.NetworkSettings.Ports {
			if len(bindings) > 0 {
				portMappings[string(containerPort)] = PortBinding{
					HostIP:   bindings[0].HostIP,
					HostPort: bindings[0].HostPort,
					Protocol: strings.Split(string(containerPort), "/")[1],
				}
			}
		}

		var health string = inspect.State.Status
		if inspect.State.Health != nil {
			health = inspect.State.Health.Status
		}

		newContainers[container.ID] = &ContainerInfo{
			ID:           container.ID,
			Name:         strings.TrimPrefix(inspect.Name, "/"),
			ServiceName:  serviceName,
			PortMappings: portMappings,
			LastUpdated:  time.Now(),
			Health:       health,
		}
	}

	cr.containers = newContainers
	return nil
}

func (cr *ContainerResolver) getServiceName(inspect types.ContainerJSON) string {
	// Check for service name in labels
	if serviceName, ok := inspect.Config.Labels["com.docker.swarm.service.name"]; ok {
		return serviceName
	}
	if serviceName, ok := inspect.Config.Labels["service.name"]; ok {
		return serviceName
	}

	// Fall back to container name without prefix
	return strings.TrimPrefix(inspect.Name, "/")
}

// ResolveTarget resolves a service name and port to the actual host and port to connect to
func (cr *ContainerResolver) ResolveTarget(serviceName string, containerPort string) (string, int, error) {
	cr.mu.RLock()
	defer cr.mu.RUnlock()

	// Find container by service name
	for _, container := range cr.containers {
		if container.ServiceName == serviceName {
			// Find port mapping
			for _, binding := range container.PortMappings {
				bindingPort := fmt.Sprintf("%s/%s", binding.HostPort, binding.Protocol)
				// DBG: log.Printf("\033[38;5;240m[DBG]\033[0m ==> Port mappings for %s %s => %s:%s/%s\n", serviceName, host, binding.HostIP, binding.HostPort, binding.Protocol)
				// DBG: log.Printf("\033[38;5;240m[DBG]\033[0m ==> \tComparing %s to %s\n", containerPort, bindingPort)

				if containerPort == bindingPort {
					hostIP := binding.HostIP
					if hostIP == "0.0.0.0" {
						hostIP = "127.0.0.1" // Use localhost when binding is on all interfaces
					}

					port, err := strconv.Atoi(binding.HostPort)
					return hostIP, port, err
				}
			}
			return "", 0, fmt.Errorf("port %s not found for service %s", containerPort, serviceName)
		}
	}
	return "", 0, fmt.Errorf("service %s not found", serviceName)
}
