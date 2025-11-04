package config

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

type EllaCoreConfig struct {
	N2Address string
}

type GnbConfig struct {
	N2Address string
}

type Config struct {
	EllaCore EllaCoreConfig
	Gnb      GnbConfig
}

type EllaCoreYAML struct {
	N2Address string `yaml:"n2-address"`
}

type GnbYAML struct {
	N2Address string `yaml:"n2-address"`
}

type ConfigYAML struct {
	EllaCore EllaCoreYAML `yaml:"ella-core"`
	Gnb      GnbYAML      `yaml:"gnb"`
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

	if c.EllaCore == (EllaCoreYAML{}) {
		return Config{}, errors.New("ella-core section is missing")
	}

	if c.EllaCore.N2Address == "" {
		return Config{}, errors.New("ella-core.n2-address is empty")
	}

	if c.Gnb == (GnbYAML{}) {
		return Config{}, errors.New("gnb section is missing")
	}

	config.EllaCore.N2Address = c.EllaCore.N2Address
	config.Gnb.N2Address = c.Gnb.N2Address

	return config, nil
}
