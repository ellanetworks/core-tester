package ue

import (
	"bytes"
	"fmt"

	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
)

type SecurityModeCompleteOpts struct {
	UESecurity   UESecurity
	UEPDUSession [16]*UEPDUSession
}

func BuildSecurityModeComplete(opts *SecurityModeCompleteOpts) ([]byte, error) {
	regReqOpts := &RegistrationRequestOpts{
		RegistrationType:  nasMessage.RegistrationType5GSInitialRegistration,
		RequestedNSSAI:    nil,
		UplinkDataStatus:  nil,
		IncludeCapability: true,
		UESecurity:        opts.UESecurity,
		UEPDUSession:      opts.UEPDUSession,
	}

	registrationRequest, err := BuildRegistrationRequest(regReqOpts)
	if err != nil {
		return nil, fmt.Errorf("error encoding %s IMSI UE  NAS Registration Request message: %v", opts.UESecurity.Supi, err)
	}

	pdu, err := buildSecurityModeComplete(registrationRequest)
	if err != nil {
		return nil, fmt.Errorf("error encoding %s IMSI UE  NAS Security Mode Complete message: %v", opts.UESecurity.Supi, err)
	}

	return pdu, nil
}

func buildSecurityModeComplete(nasMessageContainer []uint8) ([]byte, error) {
	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeSecurityModeComplete)

	securityModeComplete := nasMessage.NewSecurityModeComplete(0)
	securityModeComplete.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	securityModeComplete.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	securityModeComplete.SetSpareHalfOctet(0)
	securityModeComplete.SetMessageType(nas.MsgTypeSecurityModeComplete)

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
		securityModeComplete.SetNASMessageContainerContents(nasMessageContainer)
	}

	m.SecurityModeComplete = securityModeComplete

	data := new(bytes.Buffer)

	err := m.GmmMessageEncode(data)
	if err != nil {
		return nil, fmt.Errorf("error encoding IMSI UE  NAS Security Mode Complete message: %v", err)
	}

	nasPdu := data.Bytes()

	return nasPdu, nil
}
