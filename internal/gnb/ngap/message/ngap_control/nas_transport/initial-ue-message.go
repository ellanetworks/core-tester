/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */
package nas_transport

import (
	"fmt"

	"github.com/ellanetworks/core-tester/internal/gnb/context"
	"github.com/free5gc/aper"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

var TestPlmn ngapType.PLMNIdentity

func init() {
	TestPlmn.Value = aper.OctetString("\x02\xf8\x39")
}

func GetInitialUEMessage(ranUeNgapID int64, nasPdu []byte, guti5g *nasType.GUTI5G, gnb *context.GNBContext) ([]byte, error) {
	message := BuildInitialUEMessage(ranUeNgapID, nasPdu, guti5g, gnb)
	return ngap.Encoder(message)
}

func BuildInitialUEMessage(ranUeNgapID int64, nasPdu []byte, guti5g *nasType.GUTI5G, gnb *context.GNBContext) ngapType.NGAPPDU {
	pdu := ngapType.NGAPPDU{}
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	initiatingMessage := pdu.InitiatingMessage
	initiatingMessage.ProcedureCode.Value = ngapType.ProcedureCodeInitialUEMessage
	initiatingMessage.Criticality.Value = ngapType.CriticalityPresentIgnore

	initiatingMessage.Value.Present = ngapType.InitiatingMessagePresentInitialUEMessage
	initiatingMessage.Value.InitialUEMessage = new(ngapType.InitialUEMessage)

	initialUEMessage := initiatingMessage.Value.InitialUEMessage
	initialUEMessageIEs := &initialUEMessage.ProtocolIEs

	// RAN UE NGAP ID
	ie := ngapType.InitialUEMessageIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.InitialUEMessageIEsPresentRANUENGAPID
	ie.Value.RANUENGAPID = new(ngapType.RANUENGAPID)

	rANUENGAPID := ie.Value.RANUENGAPID
	rANUENGAPID.Value = ranUeNgapID

	initialUEMessageIEs.List = append(initialUEMessageIEs.List, ie)

	// NAS-PDU
	ie = ngapType.InitialUEMessageIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDNASPDU
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.InitialUEMessageIEsPresentNASPDU
	ie.Value.NASPDU = new(ngapType.NASPDU)

	nASPDU := ie.Value.NASPDU
	nASPDU.Value = nasPdu

	initialUEMessageIEs.List = append(initialUEMessageIEs.List, ie)

	// User Location Information
	ie = ngapType.InitialUEMessageIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDUserLocationInformation
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.InitialUEMessageIEsPresentUserLocationInformation
	ie.Value.UserLocationInformation = new(ngapType.UserLocationInformation)

	userLocationInformation := ie.Value.UserLocationInformation
	userLocationInformation.Present = ngapType.UserLocationInformationPresentUserLocationInformationNR
	userLocationInformation.UserLocationInformationNR = new(ngapType.UserLocationInformationNR)

	userLocationInformationNR := userLocationInformation.UserLocationInformationNR
	userLocationInformationNR.NRCGI.PLMNIdentity = gnb.GetPLMNIdentity()
	userLocationInformationNR.NRCGI.NRCellIdentity = gnb.GetNRCellIdentity()

	userLocationInformationNR.TAI.PLMNIdentity.Value = gnb.GetMccAndMncInOctets()
	userLocationInformationNR.TAI.TAC.Value = gnb.GetTacInBytes()

	initialUEMessageIEs.List = append(initialUEMessageIEs.List, ie)

	// RRC Establishment Cause
	ie = ngapType.InitialUEMessageIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDRRCEstablishmentCause
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.InitialUEMessageIEsPresentRRCEstablishmentCause
	ie.Value.RRCEstablishmentCause = new(ngapType.RRCEstablishmentCause)

	rRCEstablishmentCause := ie.Value.RRCEstablishmentCause
	rRCEstablishmentCause.Value = ngapType.RRCEstablishmentCausePresentMoSignalling

	initialUEMessageIEs.List = append(initialUEMessageIEs.List, ie)

	// 5G-S-TSMI (optional)
	if guti5g != nil {
		ie = ngapType.InitialUEMessageIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDFiveGSTMSI
		ie.Criticality.Value = ngapType.CriticalityPresentReject
		ie.Value.Present = ngapType.InitialUEMessageIEsPresentFiveGSTMSI
		ie.Value.FiveGSTMSI = new(ngapType.FiveGSTMSI)

		fiveGSTMSI := ie.Value.FiveGSTMSI
		fiveGSTMSI.AMFSetID.Value = aper.BitString{
			Bytes:     []byte{guti5g.Octet[5], guti5g.Octet[6]},
			BitLength: 10,
		}
		fiveGSTMSI.AMFPointer.Value = aper.BitString{
			Bytes:     []byte{guti5g.GetAMFPointer()},
			BitLength: 6,
		}
		tmsi := guti5g.GetTMSI5G()
		fiveGSTMSI.FiveGTMSI.Value = tmsi[:]

		initialUEMessageIEs.List = append(initialUEMessageIEs.List, ie)
	}
	// AMF Set ID (optional)

	// UE Context Request (optional)
	ie = ngapType.InitialUEMessageIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDUEContextRequest
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.InitialUEMessageIEsPresentUEContextRequest
	ie.Value.UEContextRequest = new(ngapType.UEContextRequest)
	ie.Value.UEContextRequest.Value = ngapType.UEContextRequestPresentRequested
	initialUEMessageIEs.List = append(initialUEMessageIEs.List, ie)

	// Allowed NSSAI (optional)
	return pdu
}

func SendInitialUeMessage(registrationRequest []byte, ue *context.GNBUe, gnb *context.GNBContext) ([]byte, error) {
	sendMsg, err := GetInitialUEMessage(ue.GetRanUeId(), registrationRequest, ue.GetTMSI(), gnb)
	if err != nil {
		return nil, fmt.Errorf("Error in %d ue initial message", ue.GetRanUeId())
	}

	return sendMsg, nil
}

/*

func InitialUEMessage(connN2 *sctp.SCTPConn, registrationRequest []byte, ue *context.RanUeContext, gnb *context.RanGnbContext) error {

	// new UE Context
	// ue.NewRanUeContext(imsi, ranUeId, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2, key, opc, "c9e8763286b5b9ffbdf56e1297d0887b", amf)

	// ueSecurityCapability := context.SetUESecurityCapability(ue)
	// registrationRequest := mm_5gs.GetRegistrationRequestWith5GMM(nasMessage.RegistrationType5GSInitialRegistration, ue.Suci, nil, nil, ueSecurityCapability)
	sendMsg, err := GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "", gnb.GetMccAndMncInOctets(), gnb.GetTacInBytes())
	if err != nil {
		return fmt.Errorf("Error in %s ue initial message", ue.Supi)
	}

	_, err = connN2.Write(sendMsg)
	if err != nil {
		return fmt.Errorf("Error sending %s ue initial message", ue.Supi)
	}

	log.WithFields(log.Fields{
		"protocol":    "NGAP",
		"source":      fmt.Sprintf("GNB[ID:%s]", gnb.GetGnbId()),
		"destination": "AMF",
		"message":     "INITIAL UE MESSAGE",
	}).Info("Sending message")

	return nil
}

*/
