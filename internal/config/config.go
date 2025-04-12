package config

import (
	"fmt"
	"os"

	"github.com/goccy/go-yaml"
	log "github.com/sirupsen/logrus"
)

var config *Config

type Config struct {
	GNodeB *GNodeB `yaml:"gnodeb"`
	Ella   *Ella   `yaml:"ella"`
	Logs   Logs    `yaml:"logs"`
}

type GNodeB struct {
	N2               IPv4Port         `yaml:"n2"`
	N3               IPv4Port         `yaml:"n3"`
	PlmnList         PlmnList         `yaml:"plmnlist"`
	SliceSupportList SliceSupportList `yaml:"slicesupportlist"`
}

type PlmnList struct {
	Mcc   string `yaml:"mcc"`
	Mnc   string `yaml:"mnc"`
	Tac   string `yaml:"tac"`
	GnbId string `yaml:"gnbid"`
}

type SliceSupportList struct {
	Sst string `yaml:"sst"`
	Sd  string `yaml:"sd"`
}

type Ella struct {
	N2 IPv4Port `yaml:"n2"`
}

type Logs struct {
	Level int `yaml:"level"`
}

func GetConfig() Config {
	return *config
}

func Load(configPath string) (Config, error) {
	c, err := readConfig(configPath)
	if err != nil {
		return c, fmt.Errorf("could not read config: %w", err)
	}
	config = &c
	setLogLevel(*config)
	return *config, nil
}

func readConfig(configPath string) (Config, error) {
	cfg := Config{}
	f, err := os.Open(configPath)
	if err != nil {
		return cfg, fmt.Errorf("could not open config at %q: %w", configPath, err)
	}
	defer f.Close()

	decoder := yaml.NewDecoder(f, yaml.Strict())
	err = decoder.Decode(&cfg)
	if err != nil {
		return cfg, fmt.Errorf("could not unmarshal yaml config: %w", err)
	}

	return cfg, nil
}

func setLogLevel(cfg Config) {
	// Output to stdout instead of the default stderr
	log.SetOutput(os.Stdout)

	if cfg.Logs.Level == 0 {
		log.SetLevel(log.InfoLevel)
	} else {
		log.SetLevel(log.Level(cfg.Logs.Level))
	}
}
