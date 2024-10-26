package nes

import "time"

type ServiceConfig struct {
	Services map[string]Service `yaml:"services" json:"services"`
	Networks map[string]Network `yaml:"networks" json:"networks"`
	Volumes  map[string]Volume  `yaml:"volumes" json:"volumes"`
	// LoadBalancer *LoadBalancerConfig `yaml:"load_balancer,omitempty"`
	Secrets    map[string]Secret `yaml:"secrets,omitempty" json:"secrets,omitempty"`
	Management map[string]string `yaml:"management,omitempty" json:"management,omitempty"`
}

type Service struct {
	Image         string            `yaml:"image" json:"image"`
	Command       []string          `yaml:"command,omitempty" json:"command,omitempty"`
	Environment   map[string]string `yaml:"environment,omitempty" json:"environment,omitempty"`
	Ports         []string          `yaml:"ports,omitempty" json:"ports,omitempty"`
	Volumes       []string          `yaml:"volumes,omitempty" json:"volumes,omitempty"`
	RestartPolicy string            `yaml:"restart_policy,omitempty" json:"restart_policy,omitempty"`
	Networks      []string          `yaml:"networks,omitempty" json:"networks,omitempty"`
	DependsOn     []string          `yaml:"depends_on,omitempty" json:"depends_on,omitempty"`
	Secrets       []string          `yaml:"secrets,omitempty" json:"secrets,omitempty"`
	Hostname      string            `yaml:"hostname,omitempty" json:"hostname,omitempty"`
	HealthCheck   *HealthCheck      `yaml:"healthcheck,omitempty" json:"healthcheck,omitempty"`
	Resources     *Resources        `yaml:"resources,omitempty" json:"resources,omitempty"`
	ExtraHosts    []string          `yaml:"extra_hosts,omitempty" json:"extra_hosts,omitempty"`
	Extras        *ServiceExtras    `yaml:"extras,omitempty" json:"extras,omitempty"`
}

type ServiceExtras struct {
	AutoUpdateService bool          `yaml:"auto_update,omitempty" json:"auto_update,omitempty"`
	Watchtime         time.Duration `yaml:"image_watch_time,omitempty" json:"image_watch_time,omitempty"`
}
