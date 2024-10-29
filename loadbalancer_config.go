package nes

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// LoadBalancerConfig represents the main configuration for the load balancer
type LoadBalancerConfig struct {
	Rules      []LoadBalancerRule  `yaml:"rules,omitempty"`
	Action     *LoadBalancerAction `yaml:"action,omitempty"`
	Domains    []string            `yaml:"domains"`
	BindIP     string              `yaml:"bind_ip,omitempty"`
	TLSCert    string              `yaml:"tls_cert,omitempty"`
	TLSKey     string              `yaml:"tls_key,omitempty"`
	UseACME    bool                `yaml:"use_acme,omitempty"`
	ACMEEmail  string              `yaml:"acme_email,omitempty"`
	ACMECache  string              `yaml:"acme_cache,omitempty"`
	Routes     map[string]Route    `yaml:"routes"`
	EnforceTLS bool                `yaml:"force_tls,omitempty"`
	Auth       AuthConfig          `yaml:"auth,omitempty"`
}

// LoadBalancerRule defines matching criteria for routing decisions
type LoadBalancerRule struct {
	Host         string            `yaml:"host,omitempty"`
	Path         string            `yaml:"path,omitempty"`
	PathRegex    string            `yaml:"path_regex,omitempty"`
	Headers      map[string]string `yaml:"headers,omitempty"`
	QueryParams  map[string]string `yaml:"query_params,omitempty"`
	Methods      []string          `yaml:"methods,omitempty"`
	Priority     int               `yaml:"priority,omitempty"`
	compiledPath *regexp.Regexp
}

// LoadBalancerAction defines what happens when rules match
type LoadBalancerAction struct {
	Type           string          `yaml:"type"` // "forward", "redirect", "fixed-response"
	Target         *Target         `yaml:"target,omitempty"`
	RedirectConfig *RedirectConfig `yaml:"redirect,omitempty"`
	FixedResponse  *FixedResponse  `yaml:"fixed_response,omitempty"`
}

// Target defines where traffic should be forwarded
type Target struct {
	Protocol string `yaml:"protocol"`
	Host     string `yaml:"host"`
	Port     string `yaml:"port"`
}

// RedirectConfig defines redirect behavior
type RedirectConfig struct {
	Protocol   string `yaml:"protocol,omitempty"`
	Host       string `yaml:"host,omitempty"`
	Path       string `yaml:"path,omitempty"`
	StatusCode int    `yaml:"status_code,omitempty"`
	StripQuery bool   `yaml:"strip_query,omitempty"`
}

// FixedResponse defines a static response
type FixedResponse struct {
	StatusCode int               `yaml:"status_code"`
	Headers    map[string]string `yaml:"headers,omitempty"`
	Body       string            `yaml:"body,omitempty"`
}

// Route defines routing configuration for a path
type Route struct {
	Service   string             `yaml:"service"`
	Port      string             `yaml:"port"`
	Protocols []string           `yaml:"protocols"`
	Auth      AuthConfig         `yaml:"auth,omitempty"`
	Rules     []LoadBalancerRule `yaml:"rules,omitempty"`
	SSL       *SSLConfig         `yaml:"ssl,omitempty"`
}

// AuthConfig defines authentication methods
type AuthConfig struct {
	Type      string           `yaml:"type"` // "none", "oauth2", "mutual_tls", "api_key"
	OAuth2    *OAuth2Config    `yaml:"oauth2,omitempty"`
	MutualTLS *MutualTLSConfig `yaml:"mutual_tls,omitempty"`
	APIKey    *APIKeyConfig    `yaml:"api_key,omitempty"`
}

// OAuth2Config defines OAuth2 authentication settings
type OAuth2Config struct {
	Provider     string   `yaml:"provider"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	Scopes       []string `yaml:"scopes,omitempty"`
	AuthURL      string   `yaml:"auth_url"`
	TokenURL     string   `yaml:"token_url"`
	CallbackURL  string   `yaml:"callback_url"`
}

// MutualTLSConfig defines mTLS settings
type MutualTLSConfig struct {
	ClientCACert string `yaml:"client_ca_cert"`
	VerifyDepth  int    `yaml:"verify_depth,omitempty"`
}

// APIKeyConfig defines API key authentication
type APIKeyConfig struct {
	Header string            `yaml:"header,omitempty"`
	Keys   map[string]string `yaml:"keys"` // key -> role mapping
}

// SSLConfig defines SSL/TLS configuration
type SSLConfig struct {
	Certificate string   `yaml:"certificate,omitempty"`
	Key         string   `yaml:"key,omitempty"`
	UseACME     bool     `yaml:"use_acme,omitempty"`
	ACMEEmail   string   `yaml:"acme_email,omitempty"`
	ACMEDomains []string `yaml:"acme_domains,omitempty"`
	MinVersion  string   `yaml:"min_version,omitempty"` // "1.2", "1.3"
	Ciphers     []string `yaml:"ciphers,omitempty"`
}

// Validate performs validation of the configuration
func (c *LoadBalancerConfig) Validate() error {
	if len(c.Domains) == 0 {
		return fmt.Errorf("at least one domain must be specified")
	}

	if c.UseACME && c.ACMEEmail == "" {
		return fmt.Errorf("ACME email is required when UseACME is true")
	}

	for path, route := range c.Routes {
		if err := validatePath(path); err != nil {
			return fmt.Errorf("invalid path %s: %w", path, err)
		}
		if err := route.validate(); err != nil {
			return fmt.Errorf("invalid route for path %s: %w", path, err)
		}
	}

	return nil
}

// validate performs validation of a Route
func (r *Route) validate() error {
	var err error
	if r.Service == "" {
		return fmt.Errorf("service name is required")
	}

	p := strings.Split(r.Port, "/")
	if len(p) != 2 {
		return fmt.Errorf("invalid port syntax, use <number>/<proto>")
	}

	var port int
	if port, err = strconv.Atoi(p[0]); err != nil {
		return fmt.Errorf("port number must be number")
	}

	if port <= 0 || port > 65535 {
		return fmt.Errorf("invalid port number: %d", port)
	}

	if len(r.Protocols) == 0 {
		return fmt.Errorf("at least one protocol must be specified")
	}

	for _, protocol := range r.Protocols {
		if !isValidProtocol(protocol) {
			return fmt.Errorf("invalid protocol: %s", protocol)
		}
	}

	if r.Auth.Type != "" {
		if err := r.Auth.validate(); err != nil {
			return fmt.Errorf("invalid auth config: %w", err)
		}
	}

	return nil
}

// validate performs validation of AuthConfig
func (a *AuthConfig) validate() error {
	switch a.Type {
	case "none":
		return nil
	case "oauth2":
		if a.OAuth2 == nil {
			return fmt.Errorf("oauth2 configuration required when type is oauth2")
		}
		return a.OAuth2.validate()
	case "mutual_tls":
		if a.MutualTLS == nil {
			return fmt.Errorf("mutual_tls configuration required when type is mutual_tls")
		}
		return a.MutualTLS.validate()
	case "api_key":
		if a.APIKey == nil {
			return fmt.Errorf("api_key configuration required when type is api_key")
		}
		return a.APIKey.validate()
	default:
		return fmt.Errorf("invalid auth type: %s", a.Type)
	}
}

// validate performs validation of OAuth2Config
func (o *OAuth2Config) validate() error {
	if o.ClientID == "" {
		return fmt.Errorf("client_id is required")
	}
	if o.ClientSecret == "" {
		return fmt.Errorf("client_secret is required")
	}
	if o.AuthURL == "" {
		return fmt.Errorf("auth_url is required")
	}
	if o.TokenURL == "" {
		return fmt.Errorf("token_url is required")
	}
	if _, err := url.Parse(o.AuthURL); err != nil {
		return fmt.Errorf("invalid auth_url: %w", err)
	}
	if _, err := url.Parse(o.TokenURL); err != nil {
		return fmt.Errorf("invalid token_url: %w", err)
	}
	return nil
}

// validate performs validation of MutualTLSConfig
func (m *MutualTLSConfig) validate() error {
	if m.ClientCACert == "" {
		return fmt.Errorf("client_ca_cert is required")
	}
	return nil
}

// validate performs validation of APIKeyConfig
func (a *APIKeyConfig) validate() error {
	if len(a.Keys) == 0 {
		return fmt.Errorf("at least one API key must be specified")
	}
	return nil
}

// Compile prepares the LoadBalancerRule for use
func (r *LoadBalancerRule) Compile() error {
	if r.PathRegex != "" {
		compiled, err := regexp.Compile(r.PathRegex)
		if err != nil {
			return fmt.Errorf("invalid path regex %s: %w", r.PathRegex, err)
		}
		r.compiledPath = compiled
	}
	return nil
}

// Match checks if the request matches this rule
func (r *LoadBalancerRule) Match(host, path string, headers map[string]string, query url.Values, method string) bool {
	if r.Host != "" && r.Host != host {
		return false
	}

	if r.Path != "" && r.Path != path {
		return false
	}

	if r.PathRegex != "" && r.compiledPath != nil && !r.compiledPath.MatchString(path) {
		return false
	}

	if len(r.Methods) > 0 {
		methodMatch := false
		for _, m := range r.Methods {
			if m == method {
				methodMatch = true
				break
			}
		}
		if !methodMatch {
			return false
		}
	}

	for k, v := range r.Headers {
		if headers[k] != v {
			return false
		}
	}

	for k, v := range r.QueryParams {
		if !query.Has(k) || query.Get(k) != v {
			return false
		}
	}

	return true
}

// Helper functions
func validatePath(path string) error {
	if !regexp.MustCompile(`^/`).MatchString(path) {
		return fmt.Errorf("path must start with /")
	}
	return nil
}

func isValidProtocol(protocol string) bool {
	validProtocols := map[string]bool{
		"http":      true,
		"https":     true,
		"grpc":      true,
		"grpcs":     true,
		"websocket": true,
		"tcp":       true,
		"udp":       true,
	}
	return validProtocols[protocol]
}
