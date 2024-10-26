package nes

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"github.com/docker/docker/api/types/mount"
)

type Secret struct {
	Type  string      `yaml:"type" json:"type"` // file, string, integer, map
	Value interface{} `yaml:"value" json:"value"`
}

// SecretManager handles secret management
type SecretManager struct {
	secrets map[string]Secret
	loaded  []string
}

func NewSecretManager(secrets map[string]Secret) *SecretManager {
	return &SecretManager{
		secrets: secrets,
		loaded:  make([]string, 0),
	}
}

func (sm *SecretManager) PrepareSecrets(service Service) ([]mount.Mount, error) {
	if len(service.Secrets) == 0 {
		return nil, nil
	}

	// Create temporary directory for secrets
	tempDir, err := os.MkdirTemp("", "secrets-")
	if err != nil {
		return nil, err
	}

	// Prepare secrets JSON
	secretsMap := make(map[string]interface{})
	for _, secretName := range service.Secrets {
		secret, exists := sm.secrets[secretName]
		if !exists {
			continue
		}

		switch secret.Type {
		case "file":
			// Copy file to temp directory
			srcPath := secret.Value.(string)
			destPath := filepath.Join(tempDir, filepath.Base(srcPath))
			if err := copyFile(srcPath, destPath); err != nil {
				return nil, err
			}
			secretsMap[secretName] = destPath
		default:
			secretsMap[secretName] = secret.Value
		}
	}

	// Write secrets to JSON file
	secretsJSON, err := json.Marshal(secretsMap)
	if err != nil {
		return nil, err
	}

	secretsPath := filepath.Join(tempDir, "secrets.json")
	if err := os.WriteFile(secretsPath, secretsJSON, 0600); err != nil {
		return nil, err
	}

	sm.loaded = append(sm.loaded, tempDir)

	return []mount.Mount{
		{
			Type:   mount.TypeBind,
			Source: secretsPath,
			Target: "/secrets.json",
		},
	}, nil
}

func copyFile(src, dst string) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()

	_, err = io.Copy(destination, source)
	return err
}

func (sm *SecretManager) Cleanup() error {
	for _, p := range sm.loaded {
		if err := os.RemoveAll(p); err != nil {
			return err
		}
	}

	return nil
}
