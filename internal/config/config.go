package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Output        string
	Timeout       time.Duration
	Engine        string
	ExcludeChecks []string
}

const defaultConfigContent = `# kvirtbp configuration file
# All values can also be set via environment variables prefixed with KVIRTBP_
# e.g. KVIRTBP_OUTPUT=json

# Output format: table|json
output: table

# Scan timeout (e.g. 30s, 2m)
timeout: 30s

# Evaluator engine: go|rego
engine: go

# Check IDs to exclude from every scan (can also be passed via --exclude-check)
exclude_checks: []
`

// defaultConfigPath returns $HOME/.config/kvirtbp/config.yaml.
func defaultConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "kvirtbp", "config.yaml"), nil
}

// ensureDefaultConfig silently creates the default config file if neither the
// explicit path nor any auto-discovered config file exists yet.
func ensureDefaultConfig() {
	path, err := defaultConfigPath()
	if err != nil {
		return
	}
	if _, err := os.Stat(path); err == nil {
		return // already exists
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	_ = os.WriteFile(path, []byte(defaultConfigContent), 0o644)
}

// Load reads configuration from (in priority order):
//  1. The explicit path provided by the caller (--config flag)
//  2. ./kvirtbp.yaml in the current working directory
//  3. $HOME/.config/kvirtbp/config.yaml
//
// If no config file is found and no explicit path was given, a default config
// file is created at $HOME/.config/kvirtbp/config.yaml silently.
// All values can be overridden via KVIRTBP_* environment variables.
func Load(path string) (Config, error) {
	v := viper.New()
	v.SetEnvPrefix("KVIRTBP")
	v.AutomaticEnv()

	v.SetDefault("output", "table")
	v.SetDefault("timeout", "30s")
	v.SetDefault("engine", "go")
	v.SetDefault("exclude_checks", []string{})

	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return Config{}, fmt.Errorf("reading config file %q: %w", path, err)
		}
	} else {
		v.SetConfigName("kvirtbp")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		if home, err := os.UserHomeDir(); err == nil {
			v.AddConfigPath(filepath.Join(home, ".config", "kvirtbp"))
		}
		if err := v.ReadInConfig(); err != nil {
			// No config file found anywhere — generate the default one silently.
			if _, ok := err.(viper.ConfigFileNotFoundError); ok {
				ensureDefaultConfig()
			}
		}
	}

	timeout, err := time.ParseDuration(v.GetString("timeout"))
	if err != nil {
		return Config{}, err
	}

	return Config{
		Output:        v.GetString("output"),
		Timeout:       timeout,
		Engine:        v.GetString("engine"),
		ExcludeChecks: v.GetStringSlice("exclude_checks"),
	}, nil
}

