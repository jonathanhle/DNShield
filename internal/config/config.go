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
	Agent         AgentConfig         `yaml:"agent"`
	S3            S3Config            `yaml:"s3"`
	DNS           DNSConfig           `yaml:"dns"`
	Blocking      BlockingConfig      `yaml:"blocking"`
	CaptivePortal CaptivePortalConfig `yaml:"captivePortal"`
	Logging       LoggingConfig       `yaml:"logging"`

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
	RulesPath      string        `yaml:"rulesPath"`
	UpdateInterval time.Duration `yaml:"updateInterval"`
	AccessKeyID    string        `yaml:"accessKeyId,omitempty"`
	SecretKey      string        `yaml:"secretKey,omitempty"`
	LogPrefix      string        `yaml:"logPrefix,omitempty"`
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

type CaptivePortalConfig struct {
	// Enable automatic captive portal detection
	Enabled bool `yaml:"enabled"`
	// Number of requests to captive portal domains within the time window to trigger bypass
	DetectionThreshold int `yaml:"detectionThreshold"`
	// Time window for counting captive portal requests
	DetectionWindow time.Duration `yaml:"detectionWindow"`
	// How long to bypass DNS filtering when captive portal is detected
	BypassDuration time.Duration `yaml:"bypassDuration"`
	// Additional captive portal domains to monitor (beyond the built-in list)
	AdditionalDomains []string `yaml:"additionalDomains,omitempty"`
}

type LoggingConfig struct {
	Splunk SplunkConfig `yaml:"splunk"`
	S3     S3LogConfig  `yaml:"s3"`
	Local  LocalConfig  `yaml:"local"`
}

type SplunkConfig struct {
	Enabled            bool          `yaml:"enabled"`
	Endpoint           string        `yaml:"endpoint"`
	Token              string        `yaml:"token"`
	Index              string        `yaml:"index"`
	Sourcetype         string        `yaml:"sourcetype"`
	VerifyServerCert   bool          `yaml:"verifyServerCert"`
	RetryMaxAttempts   int           `yaml:"retryMaxAttempts"`
	RetryBackoffSecs   int           `yaml:"retryBackoffSecs"`
}

type S3LogConfig struct {
	Enabled        bool          `yaml:"enabled"`
	BatchInterval  time.Duration `yaml:"batchInterval"`
	Compression    string        `yaml:"compression"`
	Retention      time.Duration `yaml:"retention"`
}

type LocalConfig struct {
	BufferSize   int    `yaml:"bufferSize"`
	FallbackPath string `yaml:"fallbackPath"`
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
			LogPrefix:      "audit-logs/",
		},
		Logging: LoggingConfig{
			Splunk: SplunkConfig{
				Enabled:          false,
				Sourcetype:       "dnshield:audit",
				Index:            "dnshield-audit",
				VerifyServerCert: true,
				RetryMaxAttempts: 3,
				RetryBackoffSecs: 5,
			},
			S3: S3LogConfig{
				Enabled:       false,
				BatchInterval: 1 * time.Hour,
				Compression:   "gzip",
				Retention:     90 * 24 * time.Hour, // 90 days
			},
			Local: LocalConfig{
				BufferSize:   10000,
				FallbackPath: "~/.dnshield/audit/buffer",
			},
		},
		CaptivePortal: CaptivePortalConfig{
			Enabled:            true,
			DetectionThreshold: 3,
			DetectionWindow:    10 * time.Second,
			BypassDuration:     5 * time.Minute,
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
	Version   string    `yaml:"version"`
	Updated   time.Time `yaml:"updated"`
	Sources   []string  `yaml:"sources"`
	Domains   []string  `yaml:"domains"`
	Whitelist []string  `yaml:"whitelist"`
	Regex     []string  `yaml:"regex,omitempty"`
}
