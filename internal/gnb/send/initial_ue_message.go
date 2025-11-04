package build

import (
	"encoding/hex"
	"fmt"

	"github.com/free5gc/aper"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/ngap/ngapType"
)

type InitialUEMessageOpts struct {
	RanUENGAPID int64
	NasPDU      []byte
	Guti5g      *nasType.GUTI5G
	Mcc         string
	Mnc         string
	Tac         string
	NRCellID    string
}

func InitialUEMessage(opts *InitialUEMessageOpts) (ngapType.NGAPPDU, error) {
	if opts.Mcc == "" {
		return ngapType.NGAPPDU{}, fmt.Errorf("MCC is required to build InitialUEMessage")
	}

	if opts.Mnc == "" {
		return ngapType.NGAPPDU{}, fmt.Errorf("MNC is required to build InitialUEMessage")
	}

	if opts.NRCellID == "" {
		return ngapType.NGAPPDU{}, fmt.Errorf("NRCellID is required to build InitialUEMessage")
	}

	if opts.Tac == "" {
		return ngapType.NGAPPDU{}, fmt.Errorf("TAC is required to build InitialUEMessage")
	}

	if opts.RanUENGAPID == 0 {
		return ngapType.NGAPPDU{}, fmt.Errorf("RAN UE NGAP ID is required to build InitialUEMessage")
	}

	if opts.NasPDU == nil {
		return ngapType.NGAPPDU{}, fmt.Errorf("NAS PDU is required to build InitialUEMessage")
	}

	nrCellId, err := GetNRCellIdentity(opts.NRCellID)
	if err != nil {
		return ngapType.NGAPPDU{}, fmt.Errorf("failed to get nr cell identity: %+v", err)
	}

	plmnID, err := GetMccAndMncInOctets(opts.Mcc, opts.Mnc)
	if err != nil {
		return ngapType.NGAPPDU{}, fmt.Errorf("failed to get plmnID: %+v", err)
	}

	tac, err := GetTacInBytes(opts.Tac)
	if err != nil {
		return ngapType.NGAPPDU{}, fmt.Errorf("failed to get tac: %+v", err)
	}

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
	rANUENGAPID.Value = opts.RanUENGAPID

	initialUEMessageIEs.List = append(initialUEMessageIEs.List, ie)

	// NAS-PDU
	ie = ngapType.InitialUEMessageIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDNASPDU
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.InitialUEMessageIEsPresentNASPDU
	ie.Value.NASPDU = new(ngapType.NASPDU)

	nASPDU := ie.Value.NASPDU
	nASPDU.Value = opts.NasPDU

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
	userLocationInformationNR.NRCGI.PLMNIdentity = ngapType.PLMNIdentity{
		Value: plmnID,
	}
	userLocationInformationNR.NRCGI.NRCellIdentity = nrCellId

	userLocationInformationNR.TAI.PLMNIdentity.Value = plmnID
	userLocationInformationNR.TAI.TAC.Value = tac

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
	if opts.Guti5g != nil {
		ie = ngapType.InitialUEMessageIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDFiveGSTMSI
		ie.Criticality.Value = ngapType.CriticalityPresentReject
		ie.Value.Present = ngapType.InitialUEMessageIEsPresentFiveGSTMSI
		ie.Value.FiveGSTMSI = new(ngapType.FiveGSTMSI)

		fiveGSTMSI := ie.Value.FiveGSTMSI
		fiveGSTMSI.AMFSetID.Value = aper.BitString{
			Bytes:     []byte{opts.Guti5g.Octet[5], opts.Guti5g.Octet[6]},
			BitLength: 10,
		}
		fiveGSTMSI.AMFPointer.Value = aper.BitString{
			Bytes:     []byte{opts.Guti5g.GetAMFPointer()},
			BitLength: 6,
		}
		tmsi := opts.Guti5g.GetTMSI5G()
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

	return pdu, nil
}

func GetNRCellIdentity(gnbId string) (ngapType.NRCellIdentity, error) {
	nci, err := GetGnbIdInBytes(gnbId)
	if err != nil {
		return ngapType.NRCellIdentity{}, fmt.Errorf("could not get NRCellIdentity in bytes: %v", err)
	}

	slice := make([]byte, 2)

	return ngapType.NRCellIdentity{
		Value: aper.BitString{
			Bytes:     append(nci, slice...),
			BitLength: 36,
		},
	}, nil
}

func GetGnbIdInBytes(gnbId string) ([]byte, error) {
	resu, err := hex.DecodeString(gnbId)
	if err != nil {
		return nil, fmt.Errorf("could not decode gnbId to bytes: %v", err)
	}

	return resu, nil
}
