package nes

type Config struct {
	Services     map[string]Service  `yaml:"services"`
	Networks     map[string]Network  `yaml:"networks"`
	Volumes      map[string]Volume   `yaml:"volumes"`
	LoadBalancer *LoadBalancerConfig `yaml:"load_balancer,omitempty"`
	Secrets      map[string]Secret   `yaml:"secrets,omitempty"`
	Management   *Listener           `yaml:"management,omitempty" json:"management,omitempty"`
	Metrics      *Listener           `yaml:"metrics,omitempty" json:"metrics,omitempty"`
	DockerSocket *string             `yaml:"docker,omitempty" json:"docker,omitempty"`
}

type Listener struct {
	Addr string `yaml:"addr,omitempty" json:"addr,omitempty"`
}
