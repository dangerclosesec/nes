package nes

import (
	"context"
	"fmt"
	stdlog "log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dangerclosesec/nes/internal/metrics"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"gopkg.in/yaml.v2"
)

var (
	log = stdlog.New(os.Stdout, "\033[38;5;239m[ \033[35;5;214mmgr    \033[38;5;239m] \033[0m", stdlog.LstdFlags|stdlog.Lmsgprefix|stdlog.Lmicroseconds)
)

type Manager struct {
	Client        *client.Client
	Config        Config
	Ctx           context.Context
	LogFile       *os.File
	StreamLogs    bool
	LoadBalancer  *LoadBalancer
	ErrorChan     chan *Error
	Mu            sync.RWMutex
	ShutdownChan  chan struct{}
	SecretManager *SecretManager
	Wg            sync.WaitGroup
}

type Option func(*Manager) error

// WithLogFile sets the log file for the Manager.
// It takes a string parameter logFile which specifies the path to the log file.
// The function returns an Option which, when applied, opens the specified log file
// with the appropriate flags and permissions, and assigns it to the Manager's LogFile field.
// If the log file cannot be created or opened, an error is returned.
func WithLogFile(logFile string) Option {
	return func(m *Manager) error {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to create log file: %v", err)
		}

		m.LogFile = f
		return nil
	}
}

// WithStreamLogs is an Option that enables streaming logs for the Manager.
// When applied, it sets the StreamLogs field of the Manager to true.
func WithStreamLogs() Option {
	return func(m *Manager) error {
		m.StreamLogs = true
		return nil
	}
}

// NewManager creates a new Manager instance with the provided context, configuration file path,
// and optional configuration options. It reads and parses the configuration file, initializes
// the Docker client, and sets up the secret manager if secrets are configured.
//
// Parameters:
//   - ctx: The context for managing the lifecycle of the Manager.
//   - configPath: The file path to the configuration file.
//   - options: A variadic list of Option functions for configuring the Manager.
//
// Returns:
//   - *Manager: A pointer to the newly created Manager instance.
//   - error: An error if the Manager could not be created.
//
// The function performs the following steps:
//  1. Initializes a new Manager instance with the provided context and an error channel.
//  2. Applies the provided options to the Manager instance.
//  3. Reads and parses the configuration file.
//  4. Initializes the Docker client using the Docker socket specified in the configuration.
//  5. Sets up the secret manager if secrets are configured in the configuration file.
//
// Errors:
//   - Returns an error if the configuration file cannot be read or parsed.
//   - Returns an error if the Docker client cannot be created.
//   - Returns an error if the Docker socket configuration is missing.
func NewManager(ctx context.Context, configPath string, options ...Option) (*Manager, error) {
	m := &Manager{
		Ctx:       ctx,
		ErrorChan: make(chan *Error, 100),
	}

	for _, o := range options {
		if err := o(m); err != nil {
			log.Fatalf("error creating instance manager: %s", err)
		}
	}

	// Read and parse config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	if err := yaml.Unmarshal(data, &m.Config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	if m.Config.DockerSocket == nil {
		return nil, fmt.Errorf("missing docker host configuration (default: unix:///var/run/docker.sock)")
	}

	m.Client, err = client.NewClientWithOpts(
		client.WithHost(*m.Config.DockerSocket),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %v", err)
	}

	// Initialize secret manager if secrets are configured
	if len(m.Config.Secrets) > 0 {
		m.SecretManager = NewSecretManager(m.Config.Secrets)
	}

	return m, nil
}

// UseShutdownChannel
func (m *Manager) UseShutdownChannel(shutdownChan chan struct{}) {
	m.ShutdownChan = shutdownChan
}

// Cleanup runs post process exit
func (m *Manager) Cleanup() {

	if err := m.StopServices(); err != nil {
		log.Fatalf("failed to stop services with error: %s", err)
	}

	if m.SecretManager != nil {
		if err := m.SecretManager.Cleanup(); err != nil {
			log.Fatalf("failed to cleanup secret manager with error: %s", err)
		}
	}

	if m.LogFile != nil {
		if err := m.LogFile.Close(); err != nil {
			log.Fatalf("failed to cleanup manager with error: %s", err)
		}
	}

	if m.Client != nil {
		if err := m.Client.Close(); err != nil {
			log.Fatalf("failed to cleanup manager with error: %s", err)
		}
	}

	close(m.ErrorChan)

	log.Println("Cleanup completed")
}

func (m *Manager) StartServices() error {
	// Validate configuration
	if m.Config.Services == nil {
		return fmt.Errorf("no services configured")
	}

	// Setup networks and volumes first
	if err := m.setupNetworks(); err != nil {
		return m.handleError(ErrNetwork, "Failed to setup networks", err)
	}

	if err := setupVolumes(m); err != nil {
		return m.handleError(ErrNetwork, "Failed to setup volumes", err)
	}

	// Build dependency graph and start services in order
	started := make(map[string]bool)
	var startService func(name string) error
	startService = func(name string) error {
		if started[name] {
			return nil
		}

		service, exists := m.Config.Services[name]
		if !exists {
			return m.handleError(ErrConfiguration, fmt.Sprintf("Service %s not found in configuration", name), nil)
		}

		// Start dependencies first
		for _, dep := range service.DependsOn {
			if err := startService(dep); err != nil {
				return err
			}

			// Wait for dependency to be healthy
			if err := m.waitForHealthy(dep); err != nil {
				return m.handleError(ErrContainer, fmt.Sprintf("Dependency %s for %s failed health check", dep, name), err)
			}
		}

		if err := m.StartContainer(name, service); err != nil {
			return m.handleError(ErrContainer, fmt.Sprintf("Failed to start container %s", name), err)
		}
		started[name] = true
		return nil
	}

	// Start all services
	for name := range m.Config.Services {
		if err := startService(name); err != nil {
			return err
		}
	}

	m.Mu.Lock()
	// if m.health != nil {
	// 	m.health.ActiveContainers[name] = true
	// }
	metrics.ServiceCount.Add(float64(len(m.Config.Services)))
	m.Mu.Unlock()

	return nil
}

func (m *Manager) StopServices() error {
	log.Println("Stopping all services...")

	// Create a context with timeout for shutdown operations
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get list of all containers
	containers, err := m.Client.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list containers: %v", err)
	}

	// Create a wait group for parallel shutdown
	var wg sync.WaitGroup
	errChan := make(chan error, len(containers))

	for _, c := range containers {
		// Check if this is one of our managed containers
		for _, containerName := range c.Names {
			name := strings.TrimPrefix(containerName, "/")
			if service, exists := m.Config.Services[name]; exists {
				wg.Add(1)
				go func(c types.Container, name string, service Service) {
					defer wg.Done()

					// Stop container
					log.Printf("Stopping container %s", name)
					timeout := 10
					if err := m.Client.ContainerStop(ctx, c.ID, container.StopOptions{
						Timeout: &timeout,
					}); err != nil {
						errChan <- fmt.Errorf("error stopping container %s: %v", name, err)
						return
					}

					// Remove container
					if err := m.Client.ContainerRemove(ctx, c.ID, container.RemoveOptions{
						Force: true,
					}); err != nil {
						errChan <- fmt.Errorf("error removing container %s: %v", name, err)
					}
				}(c, name, service)
			}
		}
	}

	// Wait for all containers to be processed
	wg.Wait()
	close(errChan)

	// Collect any errors
	var errors []string
	for err := range errChan {
		errors = append(errors, err.Error())
	}

	// Cancel context and wait for log collection to finish
	m.Ctx.Done()
	m.Wg.Wait()

	if len(errors) > 0 {
		return fmt.Errorf("errors during shutdown: %s", strings.Join(errors, "; "))
	}

	return nil
}

// handleError processes an error by creating a new Error instance and sending it to the ErrorChan channel.
// It returns the created Error instance.
//
// Parameters:
// - errType: The type of the error.
// - message: A descriptive message about the error.
// - err: The original error that occurred.
//
// Returns:
// - error: The newly created Error instance.
func (m *Manager) handleError(errType ErrorType, message string, err error) error {
	orchErr := NewError(errType, message, err)
	m.ErrorChan <- orchErr
	return orchErr
}
