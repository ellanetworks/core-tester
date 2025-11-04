package ue

import (
	"fmt"

	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/nas/security"
)

func SelectAlgorithms(securityCapability *nasType.UESecurityCapability) (uint8, uint8, error) {
	// set the algorithms of integrity
	var (
		integrityAlgorithm uint8
		cipheringAlgorithm uint8
	)

	if securityCapability == nil {
		return 0, 0, fmt.Errorf("securityCapability is nil")
	}

	if securityCapability.GetIA0_5G() == 1 {
		integrityAlgorithm = security.AlgIntegrity128NIA0
	} else if securityCapability.GetIA1_128_5G() == 1 {
		integrityAlgorithm = security.AlgIntegrity128NIA1
	} else if securityCapability.GetIA2_128_5G() == 1 {
		integrityAlgorithm = security.AlgIntegrity128NIA2
	} else if securityCapability.GetIA3_128_5G() == 1 {
		integrityAlgorithm = security.AlgIntegrity128NIA3
	}

	// set the algorithms of ciphering
	if securityCapability.GetEA0_5G() == 1 {
		cipheringAlgorithm = security.AlgCiphering128NEA0
	} else if securityCapability.GetEA1_128_5G() == 1 {
		cipheringAlgorithm = security.AlgCiphering128NEA1
	} else if securityCapability.GetEA2_128_5G() == 1 {
		cipheringAlgorithm = security.AlgCiphering128NEA2
	} else if securityCapability.GetEA3_128_5G() == 1 {
		cipheringAlgorithm = security.AlgCiphering128NEA3
	}

	return integrityAlgorithm, cipheringAlgorithm, nil
}
