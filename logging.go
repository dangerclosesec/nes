package nes

import (
	"bufio"
	"fmt"
	"os"

	"github.com/docker/docker/api/types/container"
)

func (m *Manager) collectLogs(containerID, name string) {
	defer m.Wg.Done()

	options := container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
		Timestamps: true,
	}

	logs, err := m.Client.ContainerLogs(m.Ctx, containerID, options)
	if err != nil {
		log.Printf("Error getting logs for container %s: %v", name, err)
		return
	}
	defer logs.Close()

	prefix := fmt.Sprintf("[%s] ", name)
	scanner := bufio.NewScanner(logs)
	for scanner.Scan() {
		text := scanner.Text()
		if len(text) > 8 { // Skip Docker's log header
			fmt.Fprintf(m.LogFile, "%s%s\n", prefix, text[8:])
		}
	}
}

func (m *Manager) streamLogs(containerID, name string) {
	defer m.Wg.Done()

	options := container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
		Timestamps: true,
	}

	logs, err := m.Client.ContainerLogs(m.Ctx, containerID, options)
	if err != nil {
		log.Printf("Error getting logs for container %s: %v", name, err)
		return
	}
	defer logs.Close()

	prefix := fmt.Sprintf("[%s] ", name)
	scanner := bufio.NewScanner(logs)
	for scanner.Scan() {
		text := scanner.Text()
		if len(text) > 8 { // Skip Docker's log header
			fmt.Fprintf(os.Stdout, "%s%s\n", prefix, text[8:])
		}
	}
}
