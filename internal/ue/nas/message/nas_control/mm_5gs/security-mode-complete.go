/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */
package mm_5gs

import (
	"bytes"
	"fmt"

	"github.com/ellanetworks/core-tester/internal/ue/context"
	"github.com/ellanetworks/core-tester/internal/ue/nas/message/nas_control"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
)

// TS 24.501 8.2.26
func getSecurityModeComplete(nasMessageContainer []uint8) ([]byte, error) {
	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeSecurityModeComplete)

	securityModeComplete := nasMessage.NewSecurityModeComplete(0)
	securityModeComplete.ExtendedProtocolDiscriminator.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	securityModeComplete.SpareHalfOctetAndSecurityHeaderType.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	securityModeComplete.SpareHalfOctetAndSecurityHeaderType.SetSpareHalfOctet(0)
	securityModeComplete.SecurityModeCompleteMessageIdentity.SetMessageType(nas.MsgTypeSecurityModeComplete)

	securityModeComplete.IMEISV = nasType.NewIMEISV(nasMessage.SecurityModeCompleteIMEISVType)
	securityModeComplete.IMEISV.SetLen(9)
	securityModeComplete.SetOddEvenIdic(0)
	securityModeComplete.SetTypeOfIdentity(nasMessage.MobileIdentity5GSTypeImeisv)
	securityModeComplete.SetIdentityDigit1(1)
	securityModeComplete.SetIdentityDigitP_1(1)
	securityModeComplete.SetIdentityDigitP(1)

	if nasMessageContainer != nil {
		securityModeComplete.NASMessageContainer = nasType.NewNASMessageContainer(nasMessage.SecurityModeCompleteNASMessageContainerType)
		securityModeComplete.NASMessageContainer.SetLen(uint16(len(nasMessageContainer)))
		securityModeComplete.NASMessageContainer.SetNASMessageContainerContents(nasMessageContainer)
	}

	m.GmmMessage.SecurityModeComplete = securityModeComplete

	data := new(bytes.Buffer)
	err := m.GmmMessageEncode(data)
	if err != nil {
		return nil, fmt.Errorf("error encoding IMSI UE  NAS Security Mode Complete message: %v", err)
	}

	nasPdu := data.Bytes()
	return nasPdu, nil
}

func SecurityModeComplete(ue *context.UEContext, rinmr uint8) ([]byte, error) {
	var registrationRequest []byte
	var err error
	if rinmr == 1 {
		registrationRequest, err = GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration, nil, nil, true, ue)
		if err != nil {
			return nil, fmt.Errorf("error encoding %s IMSI UE  NAS Registration Request message: %v", ue.UeSecurity.Supi, err)
		}
	} else {
		registrationRequest, err = GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration, nil, nil, true, ue)
		if err != nil {
			return nil, fmt.Errorf("error encoding %s IMSI UE  NAS Registration Request message: %v", ue.UeSecurity.Supi, err)
		}
	}

	pdu, err := getSecurityModeComplete(registrationRequest)
	if err != nil {
		return nil, fmt.Errorf("error encoding %s IMSI UE  NAS Security Mode Complete message: %v", ue.UeSecurity.Supi, err)
	}
	pdu, err = nas_control.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, true, true)
	if err != nil {
		return nil, fmt.Errorf("error encoding %s IMSI UE  NAS Security Mode Complete message: %v", ue.UeSecurity.Supi, err)
	}
	return pdu, nil
}
