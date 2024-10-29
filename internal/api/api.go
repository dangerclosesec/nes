package api

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	stdlog "log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dangerclosesec/nes"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

var (
	log = stdlog.New(os.Stdout, "\033[35;4;239m[ api    ]\033[0m ", stdlog.Lmicroseconds|stdlog.Lmsgprefix|stdlog.Ldate|stdlog.Lmicroseconds)
)

type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

func Handler(m *nes.Manager) http.Handler {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	// Routes
	r.Route("/api/v1", func(r chi.Router) {

		// Service operations
		r.Post("/services/start", handleStartServices(m))
		r.Post("/services/stop", handleStopServices(m))

		// Container operations
		r.Route("/containers", func(r chi.Router) {
			r.Get("/", handleListContainers(m))
			r.Route("/{name}", func(r chi.Router) {
				r.Get("/", handleGetContainer(m))
				r.Post("//start", handleStartContainer(m))
				r.Post("/stop", handleStopContainer(m))
				r.Post("/restart", handleRestartContainer(m))
				r.Post("/pull", handlePullContainer(m))
				r.Get("/health", handleContainerHealth(m))
			})
		})

		// Secret management
		r.Route("/secrets", func(r chi.Router) {
			r.Post("/", handleUpdateSecrets(m))
			r.Get("/{name}", handleGetSecret(m))
		})

		// Health checks
		r.Get("/health", handleHealthCheck(m))
	})

	return r
}

func respondWithError(w http.ResponseWriter, code int, message string, err error) {
	response := APIResponse{
		Success: false,
		Message: message,
	}
	if err != nil {
		response.Error = err.Error()
	}
	respondWithJSON(w, code, response)
}

func respondWithSuccess(w http.ResponseWriter, message string, data interface{}) {
	respondWithJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Message: message,
		Data:    data,
	})
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

// Service handlers
func handleStartServices(m *nes.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m.Mu.RLock()
		services := m.Config.Services
		m.Mu.RUnlock()

		for name, service := range services {
			// Start each service
			if err := startService(m, name, service); err != nil {
				respondWithError(w, http.StatusInternalServerError,
					fmt.Sprintf("Failed to start service %s", name), err)
				return
			}
		}
		respondWithSuccess(w, "All services started successfully", nil)
	}
}

func handleStopServices(m *nes.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		containers, err := m.Client.ContainerList(r.Context(), container.ListOptions{})
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, "Failed to list containers", err)
			return
		}

		timeout := 10 // 10 second timeout
		for _, ctnr := range containers {
			if err := m.Client.ContainerStop(r.Context(), ctnr.ID, container.StopOptions{
				Timeout: &timeout,
			}); err != nil {
				respondWithError(w, http.StatusInternalServerError,
					fmt.Sprintf("Failed to stop container %s", ctnr.ID), err)
				return
			}
		}
		respondWithSuccess(w, "All services stopped successfully", nil)
	}
}

func handleListContainers(m *nes.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get query parameters for filtering
		filters := r.URL.Query()
		showAll := filters.Get("all") == "true"
		labelFilter := filters.Get("label")

		// Create container list options
		opts := container.ListOptions{
			All: showAll,
		}

		// Add label filter if specified
		if labelFilter != "" {
			opts.Filters.Add("label", labelFilter)
		}

		// Get containers from Docker
		containers, err := m.Client.ContainerList(r.Context(), opts)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, "Failed to list containers", err)
			return
		}

		// Create enhanced response with additional information
		type ContainerInfo struct {
			types.Container
			ServiceConfig *nes.Service          `json:"service_config,omitempty"`
			DetailedState *types.ContainerState `json:"detailed_state,omitempty"`
		}

		enhancedContainers := make([]ContainerInfo, 0, len(containers))

		for _, container := range containers {
			info := ContainerInfo{
				Container: container,
			}

			// Find matching service configuration
			serviceName := strings.TrimPrefix(container.Names[0], "/")
			m.Mu.RLock()
			if service, exists := m.Config.Services[serviceName]; exists {
				info.ServiceConfig = &service
			}
			m.Mu.RUnlock()

			// Get detailed container state if available
			if details, err := m.Client.ContainerInspect(r.Context(), container.ID); err == nil {
				info.DetailedState = details.State
			}

			enhancedContainers = append(enhancedContainers, info)
		}

		respondWithSuccess(w, "", map[string]interface{}{
			"total":      len(enhancedContainers),
			"containers": enhancedContainers,
		})
	}
}

type ContainerResponse struct {
	Config    *nes.Service        `json:"service_config,omitempty"`
	Container types.ContainerJSON `json:"container"`
	Resources struct {
		Memory    float64 `json:"memory_usage_mb,omitempty"`
		CPU       float64 `json:"cpu_usage_percent,omitempty"`
		DiskRead  int64   `json:"disk_read_bytes,omitempty"`
		DiskWrite int64   `json:"disk_write_bytes,omitempty"`
	} `json:"resources"`
	Networks map[string]*network.EndpointSettings `json:"networks"`
	Volumes  map[string]struct{}                  `json:"volumes"`
	Ports    []types.Port                         `json:"ports"`
	Labels   map[string]string                    `json:"labels"`
	LogTail  []string                             `json:"recent_logs,omitempty"`
}

func handleGetContainer(m *nes.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		name := chi.URLParam(r, "name")
		var response = ContainerResponse{}

		if _, ok := m.Config.Services[name]; !ok {
			respondWithError(w, http.StatusNotFound, "Service not found", nil)
			return
		}

		config := m.Config.Services[name]
		response.Config = &config

		// Try to find container by name or ID
		cntr, err := m.Client.ContainerInspect(r.Context(), name)
		if err != nil {
			response.Container.Name = name
			response.Container.State.Health = &types.Health{Status: "offline"}
			respondWithSuccess(w, "", response)
			return
		}

		// Get matching service configuration
		serviceName := strings.TrimPrefix(cntr.Name, "/")
		m.Mu.RLock()
		service, serviceExists := m.Config.Services[serviceName]
		m.Mu.RUnlock()

		// Build response with combined information
		response = ContainerResponse{
			Container: cntr,
			Networks:  cntr.NetworkSettings.Networks,
			Volumes:   cntr.Config.Volumes,
			Labels:    cntr.Config.Labels,
		}

		// Add service configuration if available
		if serviceExists {
			response.Config = &service
		}

		// Get container stats if running
		if cntr.State.Running {
			stats, err := m.Client.ContainerStats(r.Context(), cntr.ID, false)
			if err == nil {
				var statsJSON container.Stats
				if err := json.NewDecoder(stats.Body).Decode(&statsJSON); err == nil {
					// Convert memory usage to MB
					response.Resources.Memory = float64(statsJSON.MemoryStats.Usage) / 1024 / 1024

					// Calculate CPU usage percentage
					cpuDelta := float64(statsJSON.CPUStats.CPUUsage.TotalUsage - statsJSON.PreCPUStats.CPUUsage.TotalUsage)
					systemDelta := float64(statsJSON.CPUStats.SystemUsage - statsJSON.PreCPUStats.SystemUsage)
					if systemDelta > 0 && cpuDelta > 0 {
						response.Resources.CPU = (cpuDelta / systemDelta) * 100
					}

					// Add IO stats
					if len(statsJSON.BlkioStats.IoServiceBytesRecursive) == 2 {
						response.Resources.DiskRead = int64(statsJSON.BlkioStats.IoServiceBytesRecursive[0].Value)
						response.Resources.DiskWrite = int64(statsJSON.BlkioStats.IoServiceBytesRecursive[1].Value)
					}
				}
				stats.Body.Close()
			}

			// Get recent logs if container is running
			logsReader, err := m.Client.ContainerLogs(r.Context(), cntr.ID, container.LogsOptions{
				ShowStdout: true,
				ShowStderr: true,
				Tail:       "10",
			})
			if err == nil {
				logs := make([]string, 0)
				scanner := bufio.NewScanner(logsReader)
				for scanner.Scan() && len(logs) < 10 {
					logs = append(logs, scanner.Text())
				}
				response.LogTail = logs
				logsReader.Close()
			}
		}

		respondWithSuccess(w, "", response)
	}
}

func handleStartContainer(m *nes.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")

		m.Mu.RLock()
		service, exists := m.Config.Services[name]
		m.Mu.RUnlock()

		if !exists {
			respondWithError(w, http.StatusNotFound, "Service not found", nil)
			return
		}

		if err := startService(m, name, service); err != nil {
			respondWithError(w, http.StatusInternalServerError, "Failed to start container", err)
			return
		}
		respondWithSuccess(w, fmt.Sprintf("Container %s started successfully", name), nil)
	}
}

func handleStopContainer(m *nes.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		timeout := 10 // 10 second timeout

		containerID, err := getContainerIDByName(m, name)
		if err != nil {
			respondWithError(w, http.StatusNotFound, "Container not found", err)
			return
		}

		if err := m.Client.ContainerStop(r.Context(), containerID, container.StopOptions{
			Timeout: &timeout,
		}); err != nil {
			respondWithError(w, http.StatusInternalServerError, "Failed to stop container", err)
			return
		}

		respondWithSuccess(w, fmt.Sprintf("Container %s stopped successfully", name), nil)
	}
}

func handleRestartContainer(m *nes.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		timeout := 10

		containerID, err := getContainerIDByName(m, name)
		if err != nil {
			respondWithError(w, http.StatusNotFound, "Container not found", err)
			return
		}

		if err := m.Client.ContainerRestart(r.Context(), containerID, container.StopOptions{
			Timeout: &timeout,
		}); err != nil {
			respondWithError(w, http.StatusInternalServerError, "Failed to restart container", err)
			return
		}

		respondWithSuccess(w, fmt.Sprintf("Container %s restarted successfully", name), nil)
	}
}

func handlePullContainer(m *nes.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")

		m.Mu.RLock()
		service, exists := m.Config.Services[name]
		m.Mu.RUnlock()

		if !exists {
			respondWithError(w, http.StatusNotFound, "Service not found", nil)
			return
		}

		reader, err := m.Client.ImagePull(r.Context(), service.Image, image.PullOptions{})
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, "Failed to pull image", err)
			return
		}
		defer reader.Close()

		if _, err := io.Copy(io.Discard, reader); err != nil {
			respondWithError(w, http.StatusInternalServerError, "Failed to pull image", err)
			return
		}

		respondWithSuccess(w, fmt.Sprintf("Image for container %s pulled successfully", name), nil)
	}
}

func handleUpdateSecrets(m *nes.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var secretUpdate struct {
			Name  string      `json:"name"`
			Value interface{} `json:"value"`
			Type  string      `json:"type"`
		}

		if err := json.NewDecoder(r.Body).Decode(&secretUpdate); err != nil {
			respondWithError(w, http.StatusBadRequest, "Invalid request body", err)
			return
		}

		if m.SecretManager == nil {
			respondWithError(w, http.StatusInternalServerError, "Secret manager not initialized", nil)
			return
		}

		// Update the secret
		m.Mu.Lock()
		if m.Config.Secrets == nil {
			m.Config.Secrets = make(map[string]nes.Secret)
		}
		m.Config.Secrets[secretUpdate.Name] = nes.Secret{
			Type:  secretUpdate.Type,
			Value: secretUpdate.Value,
		}
		m.Mu.Unlock()

		respondWithSuccess(w, fmt.Sprintf("Secret %s updated successfully", secretUpdate.Name), nil)
	}
}

func handleGetSecret(m *nes.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")

		if m.SecretManager == nil {
			respondWithError(w, http.StatusInternalServerError, "Secret manager not initialized", nil)
			return
		}

		m.Mu.RLock()
		secret, exists := m.Config.Secrets[name]
		m.Mu.RUnlock()

		if !exists {
			respondWithError(w, http.StatusNotFound, "Secret not found", nil)
			return
		}

		respondWithSuccess(w, "", secret)
	}
}

func handleHealthCheck(m *nes.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if m.LoadBalancer == nil {
			respondWithError(w, http.StatusServiceUnavailable, "Load balancer not initialized", nil)
			return
		}

		respondWithSuccess(w, "", m.LoadBalancer.GetHealth())
	}
}

func handleContainerHealth(m *nes.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")

		container, err := m.Client.ContainerInspect(r.Context(), name)
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, "Failed to inspect container", err)
			return
		}

		healthStatus := map[string]interface{}{
			"status":    container.State.Status,
			"running":   container.State.Running,
			"exitCode":  container.State.ExitCode,
			"startedAt": container.State.StartedAt,
		}

		if container.State.Health != nil {
			healthStatus["health"] = container.State.Health.Status
			healthStatus["failingStreak"] = container.State.Health.FailingStreak
		}

		respondWithSuccess(w, "", healthStatus)
	}
}

// Helper functions
func startService(m *nes.Manager, name string, service nes.Service) error {
	return nil
}

func getContainerIDByName(m *nes.Manager, name string) (string, error) {
	containers, err := m.Client.ContainerList(m.Ctx, container.ListOptions{})
	if err != nil {
		return "", err
	}

	for _, container := range containers {
		for _, containerName := range container.Names {
			if strings.TrimPrefix(containerName, "/") == name {
				return container.ID, nil
			}
		}
	}

	return "", fmt.Errorf("container not found: %s", name)
}
