/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */
package config

import (
	"crypto/ecdh"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"

	"github.com/ellanetworks/core-tester/internal/common/sidf"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
	"github.com/goccy/go-yaml"
)

var config *Config

type Config struct {
	GNodeB   GNodeB `yaml:"gnodeb"`
	Ue       Ue     `yaml:"ue"`
	AMFs     []*AMF `yaml:"amfif"`
	LogLevel string `yaml:"log-level"`
}

type GNodeB struct {
	ControlIF        IPv4Port         `yaml:"controlif"`
	DataIF           IPv4Port         `yaml:"dataif"`
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

type Ue struct {
	Msin                   string    `yaml:"msin"`
	Key                    string    `yaml:"key"`
	Opc                    string    `yaml:"opc"`
	Amf                    string    `yaml:"amf"`
	Sqn                    string    `yaml:"sqn"`
	Dnn                    string    `yaml:"dnn"`
	ProtectionScheme       int       `yaml:"protectionScheme"`
	HomeNetworkPublicKey   string    `yaml:"homeNetworkPublicKey"`
	HomeNetworkPublicKeyID uint8     `yaml:"homeNetworkPublicKeyID"`
	RoutingIndicator       string    `yaml:"routingindicator"`
	Hplmn                  Hplmn     `yaml:"hplmn"`
	Snssai                 Snssai    `yaml:"snssai"`
	Integrity              Integrity `yaml:"integrity"`
	Ciphering              Ciphering `yaml:"ciphering"`
}

type Hplmn struct {
	Mcc string `yaml:"mcc"`
	Mnc string `yaml:"mnc"`
}
type Snssai struct {
	Sst int    `yaml:"sst"`
	Sd  string `yaml:"sd"`
}
type Integrity struct {
	Nia0 bool `yaml:"nia0"`
	Nia1 bool `yaml:"nia1"`
	Nia2 bool `yaml:"nia2"`
	Nia3 bool `yaml:"nia3"`
}
type Ciphering struct {
	Nea0 bool `yaml:"nea0"`
	Nea1 bool `yaml:"nea1"`
	Nea2 bool `yaml:"nea2"`
	Nea3 bool `yaml:"nea3"`
}

type AMF struct {
	IPv4Port
}

func GetConfig() Config {
	return *config
}

func Load(configPath string) (Config, error) {
	c, err := readConfig(configPath)
	if err != nil {
		return c, fmt.Errorf("failed to load config: %w", err)
	}
	config = &c
	return *config, nil
}

func readConfig(configPath string) (Config, error) {
	cfg := Config{}
	f, err := os.Open(configPath)
	if err != nil {
		return cfg, fmt.Errorf("could not open config at \"%s\". %w", configPath, err)
	}
	defer f.Close()

	decoder := yaml.NewDecoder(f, yaml.Strict())
	err = decoder.Decode(&cfg)
	if err != nil {
		return cfg, fmt.Errorf("could not unmarshal yaml config at \"%s\". %w", configPath, err)
	}

	sqn, err := strconv.ParseInt(cfg.Ue.Sqn, 16, 64)
	if err != nil {
		return cfg, fmt.Errorf("sqn[%s] is invalid: %w", cfg.Ue.Sqn, err)
	}
	cfg.Ue.Sqn = fmt.Sprintf("%012X", sqn)

	return cfg, nil
}

func (config *Config) GetUESecurityCapability() *nasType.UESecurityCapability {
	UESecurityCapability := &nasType.UESecurityCapability{
		Iei:    nasMessage.RegistrationRequestUESecurityCapabilityType,
		Len:    2,
		Buffer: []uint8{0x00, 0x00},
	}

	// Ciphering algorithms
	UESecurityCapability.SetEA0_5G(boolToUint8(config.Ue.Ciphering.Nea0))
	UESecurityCapability.SetEA1_128_5G(boolToUint8(config.Ue.Ciphering.Nea1))
	UESecurityCapability.SetEA2_128_5G(boolToUint8(config.Ue.Ciphering.Nea2))
	UESecurityCapability.SetEA3_128_5G(boolToUint8(config.Ue.Ciphering.Nea3))

	// Integrity algorithms
	UESecurityCapability.SetIA0_5G(boolToUint8(config.Ue.Integrity.Nia0))
	UESecurityCapability.SetIA1_128_5G(boolToUint8(config.Ue.Integrity.Nia1))
	UESecurityCapability.SetIA2_128_5G(boolToUint8(config.Ue.Integrity.Nia2))
	UESecurityCapability.SetIA3_128_5G(boolToUint8(config.Ue.Integrity.Nia3))

	return UESecurityCapability
}

func (config *Config) GetHomeNetworkPublicKey() (sidf.HomeNetworkPublicKey, error) {
	switch config.Ue.ProtectionScheme {
	case 0:
		config.Ue.HomeNetworkPublicKey = ""
		config.Ue.HomeNetworkPublicKeyID = 0
	case 1:
		key, err := hex.DecodeString(config.Ue.HomeNetworkPublicKey)
		if err != nil {
			return sidf.HomeNetworkPublicKey{}, fmt.Errorf("invalid Home Network Public Key in configuration for Profile A: %w", err)
		}

		publicKey, err := ecdh.X25519().NewPublicKey(key)
		if err != nil {
			return sidf.HomeNetworkPublicKey{}, fmt.Errorf("invalid Home Network Public Key in configuration for Profile A: %w", err)
		}

		return sidf.HomeNetworkPublicKey{
			ProtectionScheme: strconv.Itoa(config.Ue.ProtectionScheme),
			PublicKey:        publicKey,
			PublicKeyID:      strconv.Itoa(int(config.Ue.HomeNetworkPublicKeyID)),
		}, nil
	case 2:
		key, err := hex.DecodeString(config.Ue.HomeNetworkPublicKey)
		if err != nil {
			return sidf.HomeNetworkPublicKey{}, fmt.Errorf("invalid Home Network Public Key in configuration for Profile B: %w", err)
		}

		publicKey, err := ecdh.P256().NewPublicKey(key)
		if err != nil {
			return sidf.HomeNetworkPublicKey{}, fmt.Errorf("invalid Home Network Public Key in configuration for Profile B: %w", err)
		}

		return sidf.HomeNetworkPublicKey{
			ProtectionScheme: strconv.Itoa(config.Ue.ProtectionScheme),
			PublicKey:        publicKey,
			PublicKeyID:      strconv.Itoa(int(config.Ue.HomeNetworkPublicKeyID)),
		}, nil
	default:
		return sidf.HomeNetworkPublicKey{}, fmt.Errorf("invalid Protection Scheme for SUCI. Valid values are 0, 1 and 2")
	}

	return sidf.HomeNetworkPublicKey{
		ProtectionScheme: "0",
		PublicKey:        nil,
		PublicKeyID:      "0",
	}, nil
}

func boolToUint8(boolean bool) uint8 {
	if boolean {
		return 1
	} else {
		return 0
	}
}
