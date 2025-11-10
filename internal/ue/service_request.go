package ue

import (
	"bytes"
	"fmt"

	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/nas/security"
)

type ServiceRequestOpts struct {
	ServiceType      uint8
	AMFSetID         uint16
	AMFPointer       uint8
	TMSI5G           [4]uint8
	PDUSessionStatus *[16]bool
	UESecurity       *UESecurity
}

func BuildServiceRequest(opts *ServiceRequestOpts) ([]byte, error) {
	m := nas.NewMessage()
	m.GmmMessage = nas.NewGmmMessage()
	m.GmmHeader.SetMessageType(nas.MsgTypeServiceRequest)

	serviceRequest := nasMessage.NewServiceRequest(0)
	serviceRequest.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
	serviceRequest.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
	serviceRequest.SetMessageType(nas.MsgTypeServiceRequest)
	serviceRequest.SetServiceTypeValue(opts.ServiceType)
	serviceRequest.SetNasKeySetIdentifiler(uint8(opts.UESecurity.NgKsi.Ksi))
	serviceRequest.SetAMFSetID(opts.AMFSetID)
	serviceRequest.SetAMFPointer(opts.AMFPointer)
	serviceRequest.SetTypeOfIdentity(4) // 5G-S-TMSI
	serviceRequest.SetTMSI5G(opts.TMSI5G)
	serviceRequest.TMSI5GS.SetLen(7)

	m.ServiceRequest = serviceRequest

	data := new(bytes.Buffer)

	err := m.GmmMessageEncode(data)
	if err != nil {
		return nil, fmt.Errorf("could not encode GMM message: %v", err)
	}

	nasPdu := data.Bytes()
	if err = security.NASEncrypt(opts.UESecurity.CipheringAlg, opts.UESecurity.KnasEnc, opts.UESecurity.ULCount.Get(), security.Bearer3GPP,
		security.DirectionUplink, nasPdu); err != nil {
		return nasPdu, fmt.Errorf("error encrypting NAS message: %w", err)
	}

	serviceRequest.NASMessageContainer = nasType.NewNASMessageContainer(nasMessage.ServiceRequestNASMessageContainerType)
	serviceRequest.NASMessageContainer.SetLen(uint16(len(nasPdu)))
	serviceRequest.NASMessageContainer.Buffer = nasPdu

	data = new(bytes.Buffer)

	err = m.GmmMessageEncode(data)
	if err != nil {
		return nil, fmt.Errorf("could not encode GMM message: %v", err)
	}

	nasPdu = data.Bytes()

	return nasPdu, nil
}
