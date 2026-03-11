package config

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

const DefaultConfigFile = ".releaseguard.yml"

// Load reads the config file and merges it with defaults.
// If path is empty, it looks for .releaseguard.yml in the current directory.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	v := viper.New()
	if path != "" {
		v.SetConfigFile(path)
	} else {
		v.AddConfigPath(".")
		v.SetConfigName(".releaseguard")
		v.SetConfigType("yml")
	}

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// No config file found; use defaults.
			return cfg, nil
		}
		return nil, fmt.Errorf("reading config: %w", err)
	}

	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	return cfg, nil
}

// EnsureEvidenceDir creates the output evidence directory if it does not exist.
func EnsureEvidenceDir(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating evidence directory %q: %w", dir, err)
	}
	return nil
}
