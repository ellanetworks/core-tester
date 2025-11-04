package config

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

type Config struct {
	LogLevel string
}

type ConfigYAML struct {
	LogLevel string `yaml:"log-level"`
}

func Validate(filePath string) (Config, error) {
	config := Config{}

	configYaml, err := os.ReadFile(filePath) // #nosec: G304
	if err != nil {
		return Config{}, fmt.Errorf("cannot read config file: %w", err)
	}

	c := ConfigYAML{}

	if err := yaml.Unmarshal(configYaml, &c); err != nil {
		return Config{}, fmt.Errorf("cannot unmarshal config file")
	}

	if c.LogLevel == "" {
		return Config{}, errors.New("logLevel is empty")
	}

	config.LogLevel = c.LogLevel

	return config, nil
}
