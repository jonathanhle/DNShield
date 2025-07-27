// Package config defines configuration structures and loading logic for DNShield.
// It supports YAML configuration files with validation and sensible defaults.
// Configuration can be loaded from files or environment variables, with support
// for hot reloading in future versions.
package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Agent    AgentConfig    `yaml:"agent"`
	S3       S3Config       `yaml:"s3"`
	DNS      DNSConfig      `yaml:"dns"`
	Blocking BlockingConfig `yaml:"blocking"`

	// For demo purposes
	TestDomains []string `yaml:"testDomains"`
}

type AgentConfig struct {
	DNSPort   int    `yaml:"dnsPort"`
	HTTPPort  int    `yaml:"httpPort"`
	HTTPSPort int    `yaml:"httpsPort"`
	LogLevel  string `yaml:"logLevel"`
}

type S3Config struct {
	Bucket         string        `yaml:"bucket"`
	Region         string        `yaml:"region"`
	RulesPath      string        `yaml:"rulesPath"` // Deprecated, kept for compatibility
	UpdateInterval time.Duration `yaml:"updateInterval"`
	UpdateJitter   time.Duration `yaml:"updateJitter"` // Random delay to prevent thundering herd
	AccessKeyID    string        `yaml:"accessKeyId,omitempty"`
	SecretKey      string        `yaml:"secretKey,omitempty"`

	// New path structure for enterprise rules
	Paths S3Paths `yaml:"paths"`
}

type S3Paths struct {
	Base             string `yaml:"base"`             // base.yaml
	DeviceMapping    string `yaml:"deviceMapping"`    // users/device-mapping.yaml
	UserGroups       string `yaml:"userGroups"`       // users/user-groups.yaml
	GroupsDir        string `yaml:"groupsDir"`        // groups/
	UserOverridesDir string `yaml:"userOverridesDir"` // users/overrides/
}

type DNSConfig struct {
	Upstreams []string      `yaml:"upstreams"`
	CacheSize int           `yaml:"cacheSize"`
	CacheTTL  time.Duration `yaml:"cacheTTL"`
}

type BlockingConfig struct {
	DefaultAction string        `yaml:"defaultAction"`
	BlockType     string        `yaml:"blockType"`
	BlockTTL      time.Duration `yaml:"blockTTL"`
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(path string) (*Config, error) {
	// Set defaults
	cfg := &Config{
		Agent: AgentConfig{
			DNSPort:   53,
			HTTPPort:  80,
			HTTPSPort: 443,
			LogLevel:  "info",
		},
		DNS: DNSConfig{
			Upstreams: []string{"1.1.1.1", "8.8.8.8"},
			CacheSize: 10000,
			CacheTTL:  1 * time.Hour,
		},
		Blocking: BlockingConfig{
			DefaultAction: "block",
			BlockType:     "sinkhole",
			BlockTTL:      10 * time.Second,
		},
		S3: S3Config{
			UpdateInterval: 5 * time.Minute,
			UpdateJitter:   30 * time.Second,
			Paths: S3Paths{
				Base:             "base.yaml",
				DeviceMapping:    "users/device-mapping.yaml",
				UserGroups:       "users/user-groups.yaml",
				GroupsDir:        "groups/",
				UserOverridesDir: "users/overrides/",
			},
		},
	}

	// If no path specified, try default locations
	if path == "" {
		for _, p := range []string{"./config.yaml", "/etc/dnshield/config.yaml"} {
			if _, err := os.Stat(p); err == nil {
				path = p
				break
			}
		}
	}

	// If we have a config file, load it
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}

		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, err
		}
	}

	return cfg, nil
}

// Rules represents the blocklist rules fetched from S3
type Rules struct {
	Version      string    `yaml:"version"`
	Description  string    `yaml:"description,omitempty"`
	Updated      time.Time `yaml:"updated"`
	BlockSources []string  `yaml:"block_sources"` // External blocklist URLs
	BlockDomains []string  `yaml:"block_domains"` // Domains to block
	AllowDomains []string  `yaml:"allow_domains"` // Domains to never block

	// Deprecated fields for backward compatibility
	Sources   []string `yaml:"sources,omitempty"`   // Maps to BlockSources
	Domains   []string `yaml:"domains,omitempty"`   // Maps to BlockDomains
	Whitelist []string `yaml:"whitelist,omitempty"` // Maps to AllowDomains
	Regex     []string `yaml:"regex,omitempty"`
}

// DeviceMapping represents the device-to-user mapping
type DeviceMapping struct {
	Version     string                 `yaml:"version"`
	Description string                 `yaml:"description,omitempty"`
	Users       map[string]UserDevices `yaml:"users"`
}

type UserDevices struct {
	Devices []string `yaml:"devices"`
}

// UserGroups represents the user-to-group mapping
type UserGroups struct {
	Version          string              `yaml:"version"`
	Description      string              `yaml:"description,omitempty"`
	GroupAssignments map[string][]string `yaml:"group_assignments"` // group -> users
	UserOverrides    map[string]string   `yaml:"user_overrides"`    // user -> group
}

// Normalize converts deprecated field names to new ones
func (r *Rules) Normalize() {
	// Migrate deprecated fields to new fields
	if len(r.Sources) > 0 && len(r.BlockSources) == 0 {
		r.BlockSources = r.Sources
		r.Sources = nil
	}
	if len(r.Domains) > 0 && len(r.BlockDomains) == 0 {
		r.BlockDomains = r.Domains
		r.Domains = nil
	}
	if len(r.Whitelist) > 0 && len(r.AllowDomains) == 0 {
		r.AllowDomains = r.Whitelist
		r.Whitelist = nil
	}
}
