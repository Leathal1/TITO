package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds the application configuration
type Config struct {
	Collectors CollectorsConfig `yaml:"collectors"`
	Pipeline   PipelineConfig   `yaml:"pipeline"`
	API        APIConfig        `yaml:"api"`
	Reports    ReportsConfig    `yaml:"reports"`
	Logging    LoggingConfig    `yaml:"logging"`
}

// CollectorsConfig holds collector configuration
type CollectorsConfig struct {
	NVD   NVDConfig   `yaml:"nvd"`
	OSINT OSINTConfig `yaml:"osint"`
}

// NVDConfig holds NVD collector configuration
type NVDConfig struct {
	Enabled  bool `yaml:"enabled"`
	APIKey   string `yaml:"api_key"`
	DaysBack int    `yaml:"days_back"`
	Interval string `yaml:"interval"`
}

// OSINTConfig holds OSINT collector configuration
type OSINTConfig struct {
	Enabled  bool     `yaml:"enabled"`
	Feeds    []string `yaml:"feeds"`
	Interval string   `yaml:"interval"`
}

// PipelineConfig holds pipeline configuration
type PipelineConfig struct {
	MinPriority float64 `yaml:"min_priority"`
	MaxAgeDays  int     `yaml:"max_age_days"`
}

// APIConfig holds API server configuration
type APIConfig struct {
	Enabled bool   `yaml:"enabled"`
	Host    string `yaml:"host"`
	Port    int    `yaml:"port"`
}

// ReportsConfig holds report configuration
type ReportsConfig struct {
	OutputDir string   `yaml:"output_dir"`
	Formats   []string `yaml:"formats"`
}

// LoggingConfig holds logging configuration
type LoggingConfig struct{
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	File   string `yaml:"file"`
}

// Load loads configuration from a YAML file
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	// Apply defaults
	config.applyDefaults()

	return &config, nil
}

// LoadOrDefault loads configuration or returns defaults if file doesn't exist
func LoadOrDefault(path string) (*Config, error) {
	if path == "" || !fileExists(path) {
		return Default(), nil
	}
	return Load(path)
}

// Default returns the default configuration
func Default() *Config {
	config := &Config{
		Collectors: CollectorsConfig{
			NVD: NVDConfig{
				Enabled:  true,
				DaysBack: 7,
				Interval: "6h",
			},
			OSINT: OSINTConfig{
				Enabled:  true,
				Feeds:    []string{"abuse.ch", "threatfox"},
				Interval: "4h",
			},
		},
		Pipeline: PipelineConfig{
			MinPriority: 0.2,
			MaxAgeDays:  90,
		},
		API: APIConfig{
			Enabled: true,
			Host:    "0.0.0.0",
			Port:    8080,
		},
		Reports: ReportsConfig{
			OutputDir: "reports",
			Formats:   []string{"markdown", "json"},
		},
		Logging: LoggingConfig{
			Level:  "INFO",
			Format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
		},
	}

	return config
}

// applyDefaults applies default values to missing configuration
func (c *Config) applyDefaults() {
	defaults := Default()

	// Collectors defaults
	if c.Collectors.NVD.DaysBack == 0 {
		c.Collectors.NVD.DaysBack = defaults.Collectors.NVD.DaysBack
	}
	if c.Collectors.NVD.Interval == "" {
		c.Collectors.NVD.Interval = defaults.Collectors.NVD.Interval
	}

	// Pipeline defaults
	if c.Pipeline.MaxAgeDays == 0 {
		c.Pipeline.MaxAgeDays = defaults.Pipeline.MaxAgeDays
	}

	// API defaults
	if c.API.Host == "" {
		c.API.Host = defaults.API.Host
	}
	if c.API.Port == 0 {
		c.API.Port = defaults.API.Port
	}

	// Reports defaults
	if c.Reports.OutputDir == "" {
		c.Reports.OutputDir = defaults.Reports.OutputDir
	}
	if len(c.Reports.Formats) == 0 {
		c.Reports.Formats = defaults.Reports.Formats
	}

	// Logging defaults
	if c.Logging.Level == "" {
		c.Logging.Level = defaults.Logging.Level
	}
}

// Save saves the configuration to a YAML file
func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// GetNVDInterval returns the NVD collection interval as time.Duration
func (c *Config) GetNVDInterval() time.Duration {
	duration, err := time.ParseDuration(c.Collectors.NVD.Interval)
	if err != nil {
		return 6 * time.Hour // Default
	}
	return duration
}

// GetOSINTInterval returns the OSINT collection interval as time.Duration
func (c *Config) GetOSINTInterval() time.Duration {
	duration, err := time.ParseDuration(c.Collectors.OSINT.Interval)
	if err != nil {
		return 4 * time.Hour // Default
	}
	return duration
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// CreateDefault creates a default configuration file
func CreateDefault(path string) error {
	config := Default()
	return config.Save(path)
}
