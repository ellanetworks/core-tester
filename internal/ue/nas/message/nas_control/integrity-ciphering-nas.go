/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */
package nas_control

import (
	"fmt"

	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/ellanetworks/core-tester/internal/ue/context"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/security"
)

func EncodeNasPduWithSecurity(ue *context.UEContext, pdu []byte, securityHeaderType uint8, securityContextAvailable, newSecurityContext bool) ([]byte, error) {
	m := nas.NewMessage()
	err := m.PlainNasDecode(&pdu)
	if err != nil {
		return nil, err
	}
	m.SecurityHeader = nas.SecurityHeader{
		ProtocolDiscriminator: nasMessage.Epd5GSMobilityManagementMessage,
		SecurityHeaderType:    securityHeaderType,
	}
	return NASEncode(ue, m, securityContextAvailable, newSecurityContext)
}

func NASEncode(ue *context.UEContext, msg *nas.Message, securityContextAvailable bool, newSecurityContext bool) ([]byte, error) {
	var sequenceNumber uint8
	var payload []byte
	var err error
	if ue == nil {
		err = fmt.Errorf("amfUe is nil")
		return nil, err
	}
	if msg == nil {
		err = fmt.Errorf("Nas message is empty")
		return nil, err
	}

	if !securityContextAvailable {
		return msg.PlainNasEncode()
	} else {
		if newSecurityContext {
			ue.UeSecurity.ULCount.Set(0, 0)
			ue.UeSecurity.DLCount.Set(0, 0)
		}

		sequenceNumber = ue.UeSecurity.ULCount.SQN()
		payload, err = msg.PlainNasEncode()
		if err != nil {
			return nil, err
		}

		if msg.SecurityHeaderType != nas.SecurityHeaderTypeIntegrityProtected && msg.SecurityHeaderType != nas.SecurityHeaderTypeIntegrityProtectedWithNew5gNasSecurityContext {
			if err = security.NASEncrypt(ue.UeSecurity.CipheringAlg, ue.UeSecurity.KnasEnc, ue.UeSecurity.ULCount.Get(), security.Bearer3GPP,
				security.DirectionUplink, payload); err != nil {
				logger.UELog.Errorf("Error while encrypting NAS Message: %s", err)
				return nil, err
			}
		}

		// add sequence number
		payload = append([]byte{sequenceNumber}, payload[:]...)

		mac32, err := security.NASMacCalculate(ue.UeSecurity.IntegrityAlg, ue.UeSecurity.KnasInt, ue.UeSecurity.ULCount.Get(), security.Bearer3GPP, security.DirectionUplink, payload)
		if err != nil {
			logger.UELog.Errorf("Error while calculating MAC of NAS Message: %s", err)
			return nil, err
		}

		// Add mac value
		payload = append(mac32, payload[:]...)
		// Add EPD and Security Type
		msgSecurityHeader := []byte{msg.SecurityHeader.ProtocolDiscriminator, msg.SecurityHeader.SecurityHeaderType}
		payload = append(msgSecurityHeader, payload[:]...)

		// Increase UL Count
		ue.UeSecurity.ULCount.AddOne()
	}
	return payload, nil
}
