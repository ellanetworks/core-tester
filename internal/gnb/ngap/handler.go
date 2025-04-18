/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 * © Copyright 2023-2024 Valentin D'Emmanuele
 */
package ngap

import (
	"encoding/binary"
	"fmt"
	_ "net"
	"net/netip"
	"reflect"

	"github.com/ellanetworks/core-tester/internal/gnb/context"
	"github.com/ellanetworks/core-tester/internal/gnb/nas/message/sender"
	"github.com/ellanetworks/core-tester/internal/gnb/ngap/trigger"
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/free5gc/aper"
	"github.com/free5gc/ngap/ngapConvert"
	"github.com/free5gc/ngap/ngapType"
	_ "github.com/vishvananda/netlink"
)

const notInformed = "not informed"

func HandlerDownlinkNasTransport(gnb *context.GNBContext, message *ngapType.NGAPPDU) error {
	var ranUeId int64
	var amfUeId int64
	var messageNas []byte

	valueMessage := message.InitiatingMessage.Value.DownlinkNASTransport

	for _, ies := range valueMessage.ProtocolIEs.List {
		switch ies.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			if ies.Value.AMFUENGAPID == nil {
				return fmt.Errorf("amf ue ngap id is missing")
			}
			amfUeId = ies.Value.AMFUENGAPID.Value

		case ngapType.ProtocolIEIDRANUENGAPID:
			if ies.Value.RANUENGAPID == nil {
				return fmt.Errorf("ran ue ngap id is missing")
			}
			ranUeId = ies.Value.RANUENGAPID.Value

		case ngapType.ProtocolIEIDNASPDU:
			if ies.Value.NASPDU == nil {
				return fmt.Errorf("nas pdu is missing")
			}
			messageNas = ies.Value.NASPDU.Value
		}
	}

	ue := getUeFromContext(gnb, ranUeId, amfUeId)
	if ue == nil {
		return fmt.Errorf("cannot send DownlinkNASTransport message to UE with RANUEID %d as it does not know this UE", ranUeId)
	}

	// send NAS message to UE.
	sender.SendToUe(ue, messageNas)
	return nil
}

func HandlerInitialContextSetupRequest(gnb *context.GNBContext, message *ngapType.NGAPPDU) error {
	var ranUeId int64
	var amfUeId int64
	var messageNas []byte
	var sst []string
	var sd []string
	mobilityRestrict := notInformed
	var maskedImeisv string
	var ueSecurityCapabilities *ngapType.UESecurityCapabilities
	var pDUSessionResourceSetupListCxtReq *ngapType.PDUSessionResourceSetupListCxtReq

	valueMessage := message.InitiatingMessage.Value.InitialContextSetupRequest

	for _, ies := range valueMessage.ProtocolIEs.List {
		switch ies.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			if ies.Value.AMFUENGAPID == nil {
				return fmt.Errorf("amf ue ngap id is missing")
			}
			amfUeId = ies.Value.AMFUENGAPID.Value

		case ngapType.ProtocolIEIDRANUENGAPID:
			if ies.Value.RANUENGAPID == nil {
				return fmt.Errorf("ran ue ngap id is missing")
			}
			ranUeId = ies.Value.RANUENGAPID.Value

		case ngapType.ProtocolIEIDNASPDU:
			if ies.Value.NASPDU == nil {
				logger.GnbLog.Info("NAS PDU is missing")
			}
			messageNas = ies.Value.NASPDU.Value

		case ngapType.ProtocolIEIDSecurityKey:
			if ies.Value.SecurityKey == nil {
				return fmt.Errorf("security key is missing")
			}

		case ngapType.ProtocolIEIDGUAMI:
			if ies.Value.GUAMI == nil {
				return fmt.Errorf("GUAMI is missing")
			}

		case ngapType.ProtocolIEIDAllowedNSSAI:
			if ies.Value.AllowedNSSAI == nil {
				return fmt.Errorf("Allowed NSSAI is missing")
			}

			valor := len(ies.Value.AllowedNSSAI.List)
			sst = make([]string, valor)
			sd = make([]string, valor)

			// list S-NSSAI(Single – Network Slice Selection Assistance Information).
			for i, items := range ies.Value.AllowedNSSAI.List {
				if items.SNSSAI.SST.Value != nil {
					sst[i] = fmt.Sprintf("%x", items.SNSSAI.SST.Value)
				} else {
					sst[i] = notInformed
				}

				if items.SNSSAI.SD != nil {
					sd[i] = fmt.Sprintf("%x", items.SNSSAI.SD.Value)
				} else {
					sd[i] = notInformed
				}
			}

		case ngapType.ProtocolIEIDMobilityRestrictionList:
			// that field is not mandatory.
			if ies.Value.MobilityRestrictionList == nil {
				logger.GnbLog.Info("Mobility Restriction is missing")
				mobilityRestrict = notInformed
			} else {
				mobilityRestrict = fmt.Sprintf("%x", ies.Value.MobilityRestrictionList.ServingPLMN.Value)
			}

		case ngapType.ProtocolIEIDMaskedIMEISV:
			if ies.Value.MaskedIMEISV == nil {
				logger.GnbLog.Info("Masked IMEISV is missing")
				maskedImeisv = notInformed
			} else {
				maskedImeisv = fmt.Sprintf("%x", ies.Value.MaskedIMEISV.Value.Bytes)
			}

		case ngapType.ProtocolIEIDUESecurityCapabilities:
			if ies.Value.UESecurityCapabilities == nil {
				return fmt.Errorf("ue security capabilities is missing")
			}
			ueSecurityCapabilities = ies.Value.UESecurityCapabilities

		case ngapType.ProtocolIEIDPDUSessionResourceSetupListCxtReq:
			if ies.Value.PDUSessionResourceSetupListCxtReq == nil {
				return fmt.Errorf("PDUSessionResourceSetupListCxtReq is missing")
			}
			pDUSessionResourceSetupListCxtReq = ies.Value.PDUSessionResourceSetupListCxtReq
		}
	}

	ue := getUeFromContext(gnb, ranUeId, amfUeId)
	if ue == nil {
		return fmt.Errorf("cannot get ue from context")
	}
	// create UE context.
	ue.CreateUeContext(mobilityRestrict, maskedImeisv, sst, sd, ueSecurityCapabilities)

	// show UE context.
	logger.GnbLog.Info("UE Context was created with successful")
	logger.GnbLog.Info("UE RAN ID ", ue.GetRanUeId())
	logger.GnbLog.Info("UE AMF ID ", ue.GetAmfUeId())
	mcc, mnc := ue.GetUeMobility()
	logger.GnbLog.Info("UE Mobility Restrict --Plmn-- Mcc: ", mcc, " Mnc: ", mnc)
	logger.GnbLog.Info("UE Masked Imeisv: ", ue.GetUeMaskedImeiSv())
	logger.GnbLog.Info("Allowed Nssai-- Sst: ", sst, " Sd: ", sd)

	if messageNas != nil {
		sender.SendToUe(ue, messageNas)
	}

	if pDUSessionResourceSetupListCxtReq != nil {
		logger.GnbLog.Info("AMF is requesting some PDU Session to be setup during Initial Context Setup")
		for _, pDUSessionResourceSetupItemCtxReq := range pDUSessionResourceSetupListCxtReq.List {
			pduSessionId := pDUSessionResourceSetupItemCtxReq.PDUSessionID.Value
			sst := fmt.Sprintf("%x", pDUSessionResourceSetupItemCtxReq.SNSSAI.SST.Value)
			sd := notInformed
			if pDUSessionResourceSetupItemCtxReq.SNSSAI.SD != nil {
				sd = fmt.Sprintf("%x", pDUSessionResourceSetupItemCtxReq.SNSSAI.SD.Value)
			}

			pDUSessionResourceSetupRequestTransferBytes := pDUSessionResourceSetupItemCtxReq.PDUSessionResourceSetupRequestTransfer
			pDUSessionResourceSetupRequestTransfer := &ngapType.PDUSessionResourceSetupRequestTransfer{}
			err := aper.UnmarshalWithParams(pDUSessionResourceSetupRequestTransferBytes, pDUSessionResourceSetupRequestTransfer, "valueExt")
			if err != nil {
				logger.GnbLog.Error("Unable to unmarshall PDUSessionResourceSetupRequestTransfer: ", err)
				continue
			}

			var gtpTunnel *ngapType.GTPTunnel
			var upfIp string
			var teidUplink aper.OctetString
			for _, ie := range pDUSessionResourceSetupRequestTransfer.ProtocolIEs.List {
				switch ie.Id.Value {
				case ngapType.ProtocolIEIDULNGUUPTNLInformation:
					uLNGUUPTNLInformation := ie.Value.ULNGUUPTNLInformation

					gtpTunnel = uLNGUUPTNLInformation.GTPTunnel
					upfIp, _ = ngapConvert.IPAddressToString(gtpTunnel.TransportLayerAddress)
					teidUplink = gtpTunnel.GTPTEID.Value
				}
			}

			_, err = ue.CreatePduSession(pduSessionId, upfIp, sst, sd, 0, 1, 0, 0, binary.BigEndian.Uint32(teidUplink), gnb.GetUeTeid(ue))
			if err != nil {
				logger.GnbLog.Error("", err)
			}

			if pDUSessionResourceSetupItemCtxReq.NASPDU != nil {
				sender.SendToUe(ue, pDUSessionResourceSetupItemCtxReq.NASPDU.Value)
			}
		}

		msg := context.UEMessage{GNBPduSessions: ue.GetPduSessions(), GnbIp: gnb.GetN3GnbIp()}
		sender.SendMessageToUe(ue, msg)
	}

	// send Initial Context Setup Response.
	logger.GnbLog.Info("Send Initial Context Setup Response.")
	err := trigger.SendInitialContextSetupResponse(ue, gnb)
	if err != nil {
		return fmt.Errorf("error in send Initial Context Setup Response")
	}
	return nil
}

func HandlerPduSessionResourceSetupRequest(gnb *context.GNBContext, message *ngapType.NGAPPDU) error {
	var ranUeId int64
	var amfUeId int64
	var pDUSessionResourceSetupList *ngapType.PDUSessionResourceSetupListSUReq

	valueMessage := message.InitiatingMessage.Value.PDUSessionResourceSetupRequest

	for _, ies := range valueMessage.ProtocolIEs.List {
		switch ies.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:

			if ies.Value.AMFUENGAPID == nil {
				return fmt.Errorf("AMF UE ID is missing")
			}
			amfUeId = ies.Value.AMFUENGAPID.Value

		case ngapType.ProtocolIEIDRANUENGAPID:

			if ies.Value.RANUENGAPID == nil {
				return fmt.Errorf("RAN UE ID is missing")
			}
			ranUeId = ies.Value.RANUENGAPID.Value

		case ngapType.ProtocolIEIDPDUSessionResourceSetupListSUReq:

			if ies.Value.PDUSessionResourceSetupListSUReq == nil {
				return fmt.Errorf("PDUSessionResourceSetupListSUReq is missing")
			}
			pDUSessionResourceSetupList = ies.Value.PDUSessionResourceSetupListSUReq
		}
	}

	ue := getUeFromContext(gnb, ranUeId, amfUeId)
	if ue == nil {
		return fmt.Errorf("cannot get ue from context")
	}

	var configuredPduSessions []*context.GnbPDUSession
	for _, item := range pDUSessionResourceSetupList.List {
		var pduSessionId int64
		var ulTeid uint32
		var upfAddress []byte
		var messageNas []byte
		var sst string
		var sd string
		var pduSType uint64
		var qosId int64
		var fiveQi int64
		var priArp int64

		// check PDU Session NAS PDU.
		if item.PDUSessionNASPDU != nil {
			messageNas = item.PDUSessionNASPDU.Value
		} else {
			return fmt.Errorf("NAS PDU is missing")
		}

		// check pdu session id and nssai information for create a PDU Session.

		// create a PDU session(PDU SESSION ID + NSSAI).
		pduSessionId = item.PDUSessionID.Value

		if item.SNSSAI.SD != nil {
			sd = fmt.Sprintf("%x", item.SNSSAI.SD.Value)
		} else {
			sd = notInformed
		}

		if item.SNSSAI.SST.Value != nil {
			sst = fmt.Sprintf("%x", item.SNSSAI.SST.Value)
		} else {
			sst = notInformed
		}

		if item.PDUSessionResourceSetupRequestTransfer != nil {
			pdu := &ngapType.PDUSessionResourceSetupRequestTransfer{}

			err := aper.UnmarshalWithParams(item.PDUSessionResourceSetupRequestTransfer, pdu, "valueExt")
			if err == nil {
				for _, ies := range pdu.ProtocolIEs.List {
					switch ies.Id.Value {
					case ngapType.ProtocolIEIDULNGUUPTNLInformation:
						ulTeid = binary.BigEndian.Uint32(ies.Value.ULNGUUPTNLInformation.GTPTunnel.GTPTEID.Value)
						upfAddress = ies.Value.ULNGUUPTNLInformation.GTPTunnel.TransportLayerAddress.Value.Bytes

					case ngapType.ProtocolIEIDQosFlowSetupRequestList:
						for _, itemsQos := range ies.Value.QosFlowSetupRequestList.List {
							qosId = itemsQos.QosFlowIdentifier.Value
							fiveQi = itemsQos.QosFlowLevelQosParameters.QosCharacteristics.NonDynamic5QI.FiveQI.Value
							priArp = itemsQos.QosFlowLevelQosParameters.AllocationAndRetentionPriority.PriorityLevelARP.Value
						}

					case ngapType.ProtocolIEIDPDUSessionAggregateMaximumBitRate:

					case ngapType.ProtocolIEIDPDUSessionType:
						pduSType = uint64(ies.Value.PDUSessionType.Value)

					case ngapType.ProtocolIEIDSecurityIndication:
					}
				}
			} else {
				logger.GnbLog.Info("Error in decode Pdu Session Resource Setup Request Transfer")
			}
		} else {
			return fmt.Errorf("PDU Session Resource Setup Request Transfer is missing")
		}

		upfIp := fmt.Sprintf("%d.%d.%d.%d", upfAddress[0], upfAddress[1], upfAddress[2], upfAddress[3])

		// create PDU Session for GNB UE.
		pduSession, err := ue.CreatePduSession(pduSessionId, upfIp, sst, sd, pduSType, qosId, priArp, fiveQi, ulTeid, gnb.GetUeTeid(ue))
		if err != nil {
			logger.GnbLog.Error("Error in Pdu Session Resource Setup Request.")
			logger.GnbLog.Error("", err)
		}
		configuredPduSessions = append(configuredPduSessions, pduSession)

		logger.GnbLog.Info("PDU Session was created with successful.")
		logger.GnbLog.Info("PDU Session Id: ", pduSession.GetPduSessionId())
		sst, sd = ue.GetSelectedNssai(pduSession.GetPduSessionId())
		logger.GnbLog.Info("NSSAI Selected --- sst: ", sst, " sd: ", sd)
		logger.GnbLog.Info("PDU Session Type: ", pduSession.GetPduType())
		logger.GnbLog.Info("QOS Flow Identifier: ", pduSession.GetQosId())
		logger.GnbLog.Info("Uplink Teid: ", pduSession.GetTeidUplink())
		logger.GnbLog.Info("Downlink Teid: ", pduSession.GetTeidDownlink())
		logger.GnbLog.Info("Non-Dynamic-5QI: ", pduSession.GetFiveQI())
		logger.GnbLog.Info("Priority Level ARP: ", pduSession.GetPriorityARP())
		logger.GnbLog.Info("UPF Address: ", fmt.Sprintf("%d.%d.%d.%d", upfAddress[0], upfAddress[1], upfAddress[2], upfAddress[3]), " :2152")

		// send NAS message to UE.
		sender.SendToUe(ue, messageNas)

		var pduSessions [16]*context.GnbPDUSession
		pduSessions[0] = pduSession
		msg := context.UEMessage{GnbIp: gnb.GetN3GnbIp(), GNBPduSessions: pduSessions}

		sender.SendMessageToUe(ue, msg)
	}

	// send PDU Session Resource Setup Response.
	err := trigger.SendPduSessionResourceSetupResponse(configuredPduSessions, ue, gnb)
	if err != nil {
		return fmt.Errorf("unable to send PDU Session Resource Setup Response: %v", err)
	}
	return nil
}

func HandlerPduSessionReleaseCommand(gnb *context.GNBContext, message *ngapType.NGAPPDU) error {
	valueMessage := message.InitiatingMessage.Value.PDUSessionResourceReleaseCommand

	var amfUeId int64
	var ranUeId int64
	var messageNas aper.OctetString
	var pduSessionIds []ngapType.PDUSessionID

	for _, ies := range valueMessage.ProtocolIEs.List {
		switch ies.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:

			if ies.Value.AMFUENGAPID == nil {
				return fmt.Errorf("AMF UE ID is missing")
			}
			amfUeId = ies.Value.AMFUENGAPID.Value

		case ngapType.ProtocolIEIDRANUENGAPID:

			if ies.Value.RANUENGAPID == nil {
				return fmt.Errorf("RAN UE ID is missing")
			}
			ranUeId = ies.Value.RANUENGAPID.Value

		case ngapType.ProtocolIEIDNASPDU:
			if ies.Value.NASPDU == nil {
				logger.GnbLog.Info("NAS PDU is missing")
			}
			messageNas = ies.Value.NASPDU.Value

		case ngapType.ProtocolIEIDPDUSessionResourceToReleaseListRelCmd:

			if ies.Value.PDUSessionResourceToReleaseListRelCmd == nil {
				return fmt.Errorf("PDUSessionResourceToReleaseListRelCmd is missing")
			}
			pDUSessionRessourceToReleaseListRelCmd := ies.Value.PDUSessionResourceToReleaseListRelCmd

			for _, pDUSessionRessourceToReleaseItemRelCmd := range pDUSessionRessourceToReleaseListRelCmd.List {
				pduSessionIds = append(pduSessionIds, pDUSessionRessourceToReleaseItemRelCmd.PDUSessionID)
			}
		}
	}

	ue := getUeFromContext(gnb, ranUeId, amfUeId)
	if ue == nil {
		return fmt.Errorf("cannot get ue from context")
	}

	for _, pduSessionId := range pduSessionIds {
		pduSession, err := ue.GetPduSession(pduSessionId.Value)
		if pduSession == nil || err != nil {
			logger.GnbLog.Error("Unable to delete PDU Session ", pduSessionId.Value, " from UE as the PDU Session was not found. Ignoring.")
			continue
		}
		err = ue.DeletePduSession(pduSessionId.Value)
		if err != nil {
			logger.GnbLog.Error("Unable to delete PDU Session ", pduSessionId.Value, " from UE: ", err)
		}
		logger.GnbLog.Info("Successfully deleted PDU Session ", pduSessionId.Value, " from UE Context")
	}

	err := trigger.SendPduSessionReleaseResponse(pduSessionIds, ue)
	if err != nil {
		return fmt.Errorf("unable to send PDU Session Release Response: %v", err)
	}
	sender.SendToUe(ue, messageNas)
	return nil
}

func HandlerNgSetupResponse(amf *context.GNBAmf, gnb *context.GNBContext, message *ngapType.NGAPPDU) error {
	err := false
	var plmn string

	// check information about AMF and add in AMF context.
	valueMessage := message.SuccessfulOutcome.Value.NGSetupResponse

	for _, ies := range valueMessage.ProtocolIEs.List {
		switch ies.Id.Value {
		case ngapType.ProtocolIEIDAMFName:
			if ies.Value.AMFName == nil {
				logger.GnbLog.Info("Error in NG SETUP RESPONSE,AMF Name is missing")
				logger.GnbLog.Info("AMF is inactive")
				err = true
			} else {
				amfName := ies.Value.AMFName.Value
				amf.SetAmfName(amfName)
			}

		case ngapType.ProtocolIEIDServedGUAMIList:
			if ies.Value.ServedGUAMIList.List == nil {
				logger.GnbLog.Info("Error in NG SETUP RESPONSE,Serverd Guami list is missing")
				logger.GnbLog.Info("AMF is inactive")
				err = true
			}
			for _, items := range ies.Value.ServedGUAMIList.List {
				if items.GUAMI.AMFRegionID.Value.Bytes == nil {
					logger.GnbLog.Info("Error in NG SETUP RESPONSE,Served Guami list is inappropriate")
					logger.GnbLog.Info("Error in NG SETUP RESPONSE, AMFRegionId is missing")
					logger.GnbLog.Info("AMF is inactive")
					err = true
				}
				if items.GUAMI.AMFPointer.Value.Bytes == nil {
					logger.GnbLog.Info("Error in NG SETUP RESPONSE,Served Guami list is inappropriate")
					logger.GnbLog.Info("Error in NG SETUP RESPONSE, AMFPointer is missing")
					logger.GnbLog.Info("AMF is inactive")
					err = true
				}
				if items.GUAMI.AMFSetID.Value.Bytes == nil {
					logger.GnbLog.Info("Error in NG SETUP RESPONSE,Served Guami list is inappropriate")
					logger.GnbLog.Info("Error in NG SETUP RESPONSE, AMFSetId is missing")
					logger.GnbLog.Info("AMF is inactive")
					err = true
				}
			}

		case ngapType.ProtocolIEIDRelativeAMFCapacity:
			if ies.Value.RelativeAMFCapacity != nil {
				amfCapacity := ies.Value.RelativeAMFCapacity.Value
				amf.SetAmfCapacity(amfCapacity)
			}

		case ngapType.ProtocolIEIDPLMNSupportList:

			if ies.Value.PLMNSupportList == nil {
				logger.GnbLog.Info("Error in NG SETUP RESPONSE, PLMN Support list is missing")
				err = true
			}

			for _, items := range ies.Value.PLMNSupportList.List {
				plmn = fmt.Sprintf("%x", items.PLMNIdentity.Value)
				amf.AddedPlmn(plmn)

				if items.SliceSupportList.List == nil {
					logger.GnbLog.Info("Error in NG SETUP RESPONSE, PLMN Support list is inappropriate")
					logger.GnbLog.Info("Error in NG SETUP RESPONSE, Slice Support list is missing")
					err = true
				}

				for _, slice := range items.SliceSupportList.List {
					var sd string
					var sst string

					if slice.SNSSAI.SST.Value != nil {
						sst = fmt.Sprintf("%x", slice.SNSSAI.SST.Value)
					} else {
						sst = "was not informed"
					}

					if slice.SNSSAI.SD != nil {
						sd = fmt.Sprintf("%x", slice.SNSSAI.SD.Value)
					} else {
						sd = "was not informed"
					}

					// update amf slice supported
					amf.AddedSlice(sst, sd)
				}
			}
		}
	}

	if err {
		amf.SetStateInactive()
		return fmt.Errorf("AMF is inactive")
	} else {
		amf.SetStateActive()
		logger.GnbLog.Info("AMF Name: ", amf.GetAmfName())
		logger.GnbLog.Info("State of AMF: Active")
		logger.GnbLog.Info("Capacity of AMF: ", amf.GetAmfCapacity())
		for i := 0; i < amf.GetLenPlmns(); i++ {
			mcc, mnc := amf.GetPlmnSupport(i)
			logger.GnbLog.Info("PLMNs Identities Supported by AMF -- mcc: ", mcc, " mnc:", mnc)
		}
		for i := 0; i < amf.GetLenSlice(); i++ {
			sst, sd := amf.GetSliceSupport(i)
			logger.GnbLog.Info("List of AMF slices Supported by AMF -- sst:", sst, " sd:", sd)
		}
	}
	return nil
}

func HandlerNgSetupFailure(amf *context.GNBAmf, gnb *context.GNBContext, message *ngapType.NGAPPDU) {
	// check information about AMF and add in AMF context.
	valueMessage := message.UnsuccessfulOutcome.Value.NGSetupFailure

	for _, ies := range valueMessage.ProtocolIEs.List {
		switch ies.Id.Value {
		case ngapType.ProtocolIEIDCause:
			logger.GnbLog.Error("Received failure from AMF: ", causeToString(ies.Value.Cause))

		case ngapType.ProtocolIEIDTimeToWait:
			switch ies.Value.TimeToWait.Value {
			case ngapType.TimeToWaitPresentV1s:
			case ngapType.TimeToWaitPresentV2s:
			case ngapType.TimeToWaitPresentV5s:
			case ngapType.TimeToWaitPresentV10s:
			case ngapType.TimeToWaitPresentV20s:
			case ngapType.TimeToWaitPresentV60s:
			}

		case ngapType.ProtocolIEIDCriticalityDiagnostics:
		}
	}

	// redundant but useful for information about code.
	amf.SetStateInactive()

	logger.GnbLog.Info("AMF is inactive")
}

func HandlerUeContextReleaseCommand(gnb *context.GNBContext, message *ngapType.NGAPPDU) error {
	valueMessage := message.InitiatingMessage.Value.UEContextReleaseCommand

	var cause *ngapType.Cause
	var ue_id *ngapType.RANUENGAPID

	for _, ies := range valueMessage.ProtocolIEs.List {
		switch ies.Id.Value {
		case ngapType.ProtocolIEIDUENGAPIDs:
			ue_id = &ies.Value.UENGAPIDs.UENGAPIDPair.RANUENGAPID

		case ngapType.ProtocolIEIDCause:
			cause = ies.Value.Cause
		}
	}

	ue, err := gnb.GetGnbUe(ue_id.Value)
	if err != nil {
		return fmt.Errorf("amf is trying to free the context of an unknown UE")
	}
	gnb.DeleteGnBUe(ue)

	// Send UEContextReleaseComplete
	err = trigger.SendUeContextReleaseComplete(ue)
	if err != nil {
		return fmt.Errorf("unable to send UE Context Release Complete: %v", err)
	}
	logger.GnbLog.Info("Releasing UE Context, cause: ", causeToString(cause))
	return nil
}

func HandlerAmfConfigurationUpdate(amf *context.GNBAmf, gnb *context.GNBContext, message *ngapType.NGAPPDU) error {
	logger.GnbLog.Debugf("Before Update:")
	for oldAmf := range gnb.IterGnbAmf() {
		tnla := oldAmf.GetTNLA()
		logger.GnbLog.Debugf("[AMF Name: %5s], IP: %10s, AMFCapacity: %3d, TNLA Weight Factor: %2d, TNLA Usage: %2d\n",
			oldAmf.GetAmfName(), oldAmf.GetAmfIpPort().Addr(), oldAmf.GetAmfCapacity(), tnla.GetWeightFactor(), tnla.GetUsage())
	}

	var amfName string
	var amfCapacity int64
	var amfRegionId, amfSetId, amfPointer aper.BitString

	valueMessage := message.InitiatingMessage.Value.AMFConfigurationUpdate
	for _, ie := range valueMessage.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFName:
			amfName = ie.Value.AMFName.Value

		case ngapType.ProtocolIEIDServedGUAMIList:
			for _, servedGuamiItem := range ie.Value.ServedGUAMIList.List {
				amfRegionId = servedGuamiItem.GUAMI.AMFRegionID.Value
				amfSetId = servedGuamiItem.GUAMI.AMFSetID.Value
				amfPointer = servedGuamiItem.GUAMI.AMFPointer.Value
			}
		case ngapType.ProtocolIEIDRelativeAMFCapacity:
			amfCapacity = ie.Value.RelativeAMFCapacity.Value

		case ngapType.ProtocolIEIDAMFTNLAssociationToAddList:
			toAddList := ie.Value.AMFTNLAssociationToAddList
			for _, toAddItem := range toAddList.List {
				ipv4String, _ := ngapConvert.IPAddressToString(*toAddItem.AMFTNLAssociationAddress.EndpointIPAddress)
				if ipv4String == "" {
					// ignore AMF that does not have IPv4 address
					continue
				}
				ipv4Port := netip.AddrPortFrom(netip.MustParseAddr(ipv4String), 38412) // with default sctp port

				if oldAmf := gnb.FindGnbAmfByIpPort(ipv4Port); oldAmf != nil {
					logger.GnbLog.Info("SCTP/NGAP service exists")
					continue
				}

				newAmf := gnb.NewGnBAmf(ipv4Port)
				newAmf.SetAmfName(amfName)
				newAmf.SetAmfCapacity(amfCapacity)
				newAmf.SetRegionId(amfRegionId)
				newAmf.SetSetId(amfSetId)
				newAmf.SetPointer(amfPointer)
				newAmf.SetTNLAUsage(toAddItem.TNLAssociationUsage.Value)
				newAmf.SetTNLAWeight(toAddItem.TNLAddressWeightFactor.Value)

				// start communication with AMF(SCTP).
				if err := InitConn(newAmf, gnb); err != nil {
					return fmt.Errorf("could not connect to AMF: %v", err)
				} else {
					logger.GnbLog.Info("SCTP/NGAP service is running")
				}

				err := trigger.SendNgSetupRequest(gnb, newAmf)
				if err != nil {
					return fmt.Errorf("could not send NG Setup Request: %v", err)
				}
			}

		case ngapType.ProtocolIEIDAMFTNLAssociationToRemoveList:
			toRemoveList := ie.Value.AMFTNLAssociationToRemoveList
			for _, toRemoveItem := range toRemoveList.List {
				ipv4String, _ := ngapConvert.IPAddressToString(*toRemoveItem.AMFTNLAssociationAddress.EndpointIPAddress)
				if ipv4String == "" {
					// ignore AMF that does not have IPv4 address
					continue
				}
				ipv4Port := netip.AddrPortFrom(netip.MustParseAddr(ipv4String), 38412) // with default sctp port

				oldAmf := gnb.FindGnbAmfByIpPort(ipv4Port)
				if oldAmf == nil {
					continue
				}

				logger.GnbLog.Info("Remove AMF:", amf.GetAmfName(), " IP:", amf.GetAmfIpPort().Addr())
				tnla := amf.GetTNLA()
				err := tnla.Release() // Close SCTP Conntection
				if err != nil {
					logger.GnbLog.Error("Error in releasing TNLA: ", err)
				}
				gnb.DeleteGnBAmf(oldAmf.GetAmfId())
			}

		case ngapType.ProtocolIEIDAMFTNLAssociationToUpdateList:
			toUpdateList := ie.Value.AMFTNLAssociationToUpdateList
			for _, toUpdateItem := range toUpdateList.List {
				ipv4String, _ := ngapConvert.IPAddressToString(*toUpdateItem.AMFTNLAssociationAddress.EndpointIPAddress)
				if ipv4String == "" {
					// ignore AMF that does not have IPv4 address
					continue
				}
				ipv4Port := netip.AddrPortFrom(netip.MustParseAddr(ipv4String), 38412) // with default sctp port

				oldAmf := gnb.FindGnbAmfByIpPort(ipv4Port)
				if oldAmf == nil {
					continue
				}

				oldAmf.SetAmfName(amfName)
				oldAmf.SetAmfCapacity(amfCapacity)
				oldAmf.SetRegionId(amfRegionId)
				oldAmf.SetSetId(amfSetId)
				oldAmf.SetPointer(amfPointer)

				oldAmf.SetTNLAUsage(toUpdateItem.TNLAssociationUsage.Value)
				oldAmf.SetTNLAWeight(toUpdateItem.TNLAddressWeightFactor.Value)
			}

			// default:
		}
	}

	logger.GnbLog.Debugf("After Update:")
	for oldAmf := range gnb.IterGnbAmf() {
		tnla := oldAmf.GetTNLA()
		logger.GnbLog.Debugf("[AMF Name: %5s], IP: %10s, AMFCapacity: %3d, TNLA Weight Factor: %2d, TNLA Usage: %2d\n",
			oldAmf.GetAmfName(), oldAmf.GetAmfIpPort().Addr(), oldAmf.GetAmfCapacity(), tnla.GetWeightFactor(), tnla.GetUsage())
	}

	err := trigger.SendAmfConfigurationUpdateAcknowledge(amf)
	if err != nil {
		return fmt.Errorf("could not send AMF Configuration Update Acknowledge: %v", err)
	}
	return nil
}

func HandlerAmfStatusIndication(amf *context.GNBAmf, gnb *context.GNBContext, message *ngapType.NGAPPDU) {
	valueMessage := message.InitiatingMessage.Value.AMFStatusIndication
	for _, ie := range valueMessage.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDUnavailableGUAMIList:
			for _, unavailableGuamiItem := range ie.Value.UnavailableGUAMIList.List {
				octetStr := unavailableGuamiItem.GUAMI.PLMNIdentity.Value
				hexStr := fmt.Sprintf("%02x%02x%02x", octetStr[0], octetStr[1], octetStr[2])
				var unavailableMcc, unavailableMnc string
				unavailableMcc = string(hexStr[1]) + string(hexStr[0]) + string(hexStr[3])
				unavailableMnc = string(hexStr[5]) + string(hexStr[4])
				if hexStr[2] != 'f' {
					unavailableMnc = string(hexStr[2]) + string(hexStr[5]) + string(hexStr[4])
				}

				// select backup AMF
				var backupAmf *context.GNBAmf
				for oldAmf := range gnb.IterGnbAmf() {
					if unavailableGuamiItem.BackupAMFName != nil &&
						oldAmf.GetAmfName() == unavailableGuamiItem.BackupAMFName.Value {
						backupAmf = oldAmf
						break
					}
				}
				if backupAmf == nil {
					return
				}

				for oldAmf := range gnb.IterGnbAmf() {
					for j := 0; j < oldAmf.GetLenPlmns(); j++ {
						oldAmfSupportMcc, oldAmfSupportMnc := oldAmf.GetPlmnSupport(j)

						if oldAmfSupportMcc == unavailableMcc && oldAmfSupportMnc == unavailableMnc &&
							reflect.DeepEqual(oldAmf.GetRegionId(), unavailableGuamiItem.GUAMI.AMFRegionID.Value) &&
							reflect.DeepEqual(oldAmf.GetSetId(), unavailableGuamiItem.GUAMI.AMFSetID.Value) &&
							reflect.DeepEqual(oldAmf.GetPointer(), unavailableGuamiItem.GUAMI.AMFPointer.Value) {
							logger.GnbLog.Info("Remove AMF: [",
								"Id: ", oldAmf.GetAmfId(),
								"Name: ", oldAmf.GetAmfName(),
								"Ipv4: ", oldAmf.GetAmfIpPort().Addr(),
								"]",
							)

							tnla := oldAmf.GetTNLA()

							// NGAP UE-TNLA Rebinding
							uePool := gnb.GetUePool()
							uePool.Range(func(k, v any) bool {
								ue, ok := v.(*context.GNBUe)
								if !ok {
									return true
								}

								if ue.GetAmfId() == oldAmf.GetAmfId() {
									// set amfId and SCTP association for UE.
									ue.SetAmfId(backupAmf.GetAmfId())
									ue.SetSCTP(backupAmf.GetSCTPConn())
								}

								return true
							})

							prUePool := gnb.GetPrUePool()
							prUePool.Range(func(k, v any) bool {
								ue, ok := v.(*context.GNBUe)
								if !ok {
									return true
								}

								if ue.GetAmfId() == oldAmf.GetAmfId() {
									// set amfId and SCTP association for UE.
									ue.SetAmfId(backupAmf.GetAmfId())
									ue.SetSCTP(backupAmf.GetSCTPConn())
								}

								return true
							})

							err := tnla.Release()
							if err != nil {
								logger.GnbLog.Error("Error in TNLA Release: ", err)
							}
							gnb.DeleteGnBAmf(oldAmf.GetAmfId())

							break
						}
					}
				}
			}
		}
	}
}

func HandlerPathSwitchRequestAcknowledge(gnb *context.GNBContext, message *ngapType.NGAPPDU) error {
	var pduSessionResourceSwitchedList *ngapType.PDUSessionResourceSwitchedList
	valueMessage := message.SuccessfulOutcome.Value.PathSwitchRequestAcknowledge

	var amfUeId, ranUeId int64

	for _, ies := range valueMessage.ProtocolIEs.List {
		switch ies.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:

			if ies.Value.AMFUENGAPID == nil {
				return fmt.Errorf("AMF UE ID is missing")
			}
			amfUeId = ies.Value.AMFUENGAPID.Value

		case ngapType.ProtocolIEIDRANUENGAPID:

			if ies.Value.RANUENGAPID == nil {
				return fmt.Errorf("RAN UE ID is missing")
			}
			ranUeId = ies.Value.RANUENGAPID.Value

		case ngapType.ProtocolIEIDPDUSessionResourceSwitchedList:
			pduSessionResourceSwitchedList = ies.Value.PDUSessionResourceSwitchedList
			if pduSessionResourceSwitchedList == nil {
				return fmt.Errorf("PDU Session Resource Switched List is missing")
			}
		}
	}
	ue := getUeFromContext(gnb, ranUeId, amfUeId)
	if ue == nil {
		return fmt.Errorf("cannot get ue from context")
	}

	if pduSessionResourceSwitchedList == nil || len(pduSessionResourceSwitchedList.List) == 0 {
		logger.GnbLog.Warn("No PDU Sessions to be switched")
		return nil
	}

	for _, pduSessionResourceSwitchedItem := range pduSessionResourceSwitchedList.List {
		pduSessionId := pduSessionResourceSwitchedItem.PDUSessionID.Value
		pduSession, err := ue.GetPduSession(pduSessionId)
		if err != nil {
			logger.GnbLog.Error("Trying to path switch an unknown PDU Session ID ", pduSessionId, ": ", err)
			continue
		}

		pathSwitchRequestAcknowledgeTransferBytes := pduSessionResourceSwitchedItem.PathSwitchRequestAcknowledgeTransfer
		pathSwitchRequestAcknowledgeTransfer := &ngapType.PathSwitchRequestAcknowledgeTransfer{}
		err = aper.UnmarshalWithParams(pathSwitchRequestAcknowledgeTransferBytes, pathSwitchRequestAcknowledgeTransfer, "valueExt")
		if err != nil {
			logger.GnbLog.Error("Unable to unmarshall PathSwitchRequestAcknowledgeTransfer: ", err)
			continue
		}

		if pathSwitchRequestAcknowledgeTransfer.ULNGUUPTNLInformation != nil {
			gtpTunnel := pathSwitchRequestAcknowledgeTransfer.ULNGUUPTNLInformation.GTPTunnel
			upfIpv4, _ := ngapConvert.IPAddressToString(gtpTunnel.TransportLayerAddress)
			teidUplink := gtpTunnel.GTPTEID.Value

			// Set new Teid Uplink received in PathSwitchRequestAcknowledge
			pduSession.SetTeidUplink(binary.BigEndian.Uint32(teidUplink))
			pduSession.SetUpfIp(upfIpv4)
		}
		var pduSessions [16]*context.GnbPDUSession
		pduSessions[0] = pduSession

		msg := context.UEMessage{GNBPduSessions: pduSessions, GnbIp: gnb.GetN3GnbIp()}

		sender.SendMessageToUe(ue, msg)
	}

	logger.GnbLog.Info("Handover completed successfully for UE ", ue.GetRanUeId())
	return nil
}

func HandlerHandoverRequest(amf *context.GNBAmf, gnb *context.GNBContext, message *ngapType.NGAPPDU) error {
	var ueSecurityCapabilities *ngapType.UESecurityCapabilities
	var sst []string
	var sd []string
	var maskedImeisv string
	var sourceToTargetContainer *ngapType.SourceToTargetTransparentContainer
	var pDUSessionResourceSetupListHOReq *ngapType.PDUSessionResourceSetupListHOReq
	var amfUeId int64

	valueMessage := message.InitiatingMessage.Value.HandoverRequest

	for _, ies := range valueMessage.ProtocolIEs.List {
		switch ies.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			if ies.Value.AMFUENGAPID == nil {
				return fmt.Errorf("AMF UE ID is missing")
			}
			amfUeId = ies.Value.AMFUENGAPID.Value

		case ngapType.ProtocolIEIDAllowedNSSAI:
			if ies.Value.AllowedNSSAI == nil {
				return fmt.Errorf("allowed NSSAI is missing")
			}

			valor := len(ies.Value.AllowedNSSAI.List)
			sst = make([]string, valor)
			sd = make([]string, valor)

			// list S-NSSAI(Single – Network Slice Selection Assistance Information).
			for i, items := range ies.Value.AllowedNSSAI.List {
				if items.SNSSAI.SST.Value != nil {
					sst[i] = fmt.Sprintf("%x", items.SNSSAI.SST.Value)
				} else {
					sst[i] = notInformed
				}

				if items.SNSSAI.SD != nil {
					sd[i] = fmt.Sprintf("%x", items.SNSSAI.SD.Value)
				} else {
					sd[i] = notInformed
				}
			}

		case ngapType.ProtocolIEIDMaskedIMEISV:
			if ies.Value.MaskedIMEISV == nil {
				logger.GnbLog.Info("Masked IMEISV is missing")
				maskedImeisv = notInformed
			} else {
				maskedImeisv = fmt.Sprintf("%x", ies.Value.MaskedIMEISV.Value.Bytes)
			}

		case ngapType.ProtocolIEIDSourceToTargetTransparentContainer:
			sourceToTargetContainer = ies.Value.SourceToTargetTransparentContainer
			if sourceToTargetContainer == nil {
				return fmt.Errorf("sourceToTargetContainer is missing")
			}

		case ngapType.ProtocolIEIDPDUSessionResourceSetupListHOReq:
			pDUSessionResourceSetupListHOReq = ies.Value.PDUSessionResourceSetupListHOReq
			if pDUSessionResourceSetupListHOReq == nil {
				return fmt.Errorf("pDUSessionResourceSetupListHOReq is missing")
			}

		case ngapType.ProtocolIEIDUESecurityCapabilities:
			if ies.Value.UESecurityCapabilities == nil {
				return fmt.Errorf("ue Security Capabilities is missing")
			}
			ueSecurityCapabilities = ies.Value.UESecurityCapabilities
		}
	}

	if sourceToTargetContainer == nil {
		return fmt.Errorf("handoverRequest message from AMF is missing mandatory SourceToTargetTransparentContainer")
	}

	sourceToTargetContainerBytes := sourceToTargetContainer.Value
	sourceToTargetContainerNgap := &ngapType.SourceNGRANNodeToTargetNGRANNodeTransparentContainer{}
	err := aper.UnmarshalWithParams(sourceToTargetContainerBytes, sourceToTargetContainerNgap, "valueExt")
	if err != nil {
		return fmt.Errorf("unable to unmarshall SourceToTargetTransparentContainer: %w", err)
	}
	if sourceToTargetContainerNgap.IndexToRFSP == nil {
		return fmt.Errorf("sourceToTargetContainer from source gNodeB is missing IndexToRFSP")
	}
	prUeId := sourceToTargetContainerNgap.IndexToRFSP.Value

	ue, err := gnb.NewGnBUe(nil, nil, prUeId, nil)
	if ue == nil || err != nil {
		return fmt.Errorf("handover failed: %w", err)
	}
	ue.SetAmfUeId(amfUeId)

	ue.CreateUeContext(notInformed, maskedImeisv, sst, sd, ueSecurityCapabilities)

	for _, pDUSessionResourceSetupItemHOReq := range pDUSessionResourceSetupListHOReq.List {
		pduSessionId := pDUSessionResourceSetupItemHOReq.PDUSessionID.Value
		sst := fmt.Sprintf("%x", pDUSessionResourceSetupItemHOReq.SNSSAI.SST.Value)
		sd := notInformed
		if pDUSessionResourceSetupItemHOReq.SNSSAI.SD != nil {
			sd = fmt.Sprintf("%x", pDUSessionResourceSetupItemHOReq.SNSSAI.SD.Value)
		}

		handOverRequestTransferBytes := pDUSessionResourceSetupItemHOReq.HandoverRequestTransfer
		handOverRequestTransfer := &ngapType.PDUSessionResourceSetupRequestTransfer{}
		err := aper.UnmarshalWithParams(handOverRequestTransferBytes, handOverRequestTransfer, "valueExt")
		if err != nil {
			logger.GnbLog.Error("Unable to unmarshall HandOverRequestTransfer: ", err)
			continue
		}

		var gtpTunnel *ngapType.GTPTunnel
		var upfIp string
		var teidUplink aper.OctetString
		for _, ie := range handOverRequestTransfer.ProtocolIEs.List {
			switch ie.Id.Value {
			case ngapType.ProtocolIEIDULNGUUPTNLInformation:
				uLNGUUPTNLInformation := ie.Value.ULNGUUPTNLInformation

				gtpTunnel = uLNGUUPTNLInformation.GTPTunnel
				upfIp, _ = ngapConvert.IPAddressToString(gtpTunnel.TransportLayerAddress)
				teidUplink = gtpTunnel.GTPTEID.Value
			}
		}

		_, err = ue.CreatePduSession(pduSessionId, upfIp, sst, sd, 0, 1, 0, 0, binary.BigEndian.Uint32(teidUplink), gnb.GetUeTeid(ue))
		if err != nil {
			logger.GnbLog.Errorf("unable to create PDU Session %d: %s", pduSessionId, err)
		}
	}

	err = trigger.SendHandoverRequestAcknowledge(gnb, ue)
	if err != nil {
		return fmt.Errorf("unable to send HandoverRequestAcknowledge: %w", err)
	}
	return nil
}

func HandlerHandoverCommand(amf *context.GNBAmf, gnb *context.GNBContext, message *ngapType.NGAPPDU) error {
	valueMessage := message.SuccessfulOutcome.Value.HandoverCommand

	var amfUeId, ranUeId int64

	for _, ies := range valueMessage.ProtocolIEs.List {
		switch ies.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:

			if ies.Value.AMFUENGAPID == nil {
				return fmt.Errorf("amf UE ID is missing")
			}
			amfUeId = ies.Value.AMFUENGAPID.Value

		case ngapType.ProtocolIEIDRANUENGAPID:

			if ies.Value.RANUENGAPID == nil {
				return fmt.Errorf("ran UE ID is missing")
			}
			ranUeId = ies.Value.RANUENGAPID.Value
		}
	}
	ue := getUeFromContext(gnb, ranUeId, amfUeId)
	if ue == nil {
		return fmt.Errorf("cannot get ue from context")
	}
	newGnb := ue.GetHandoverGnodeB()
	if newGnb == nil {
		return fmt.Errorf("amf is sending a Handover Command for an UE we did not send a Handover Required message")
	}

	newGnbRx := make(chan context.UEMessage, 1)
	newGnbTx := make(chan context.UEMessage, 1)
	newGnb.GetInboundChannel() <- context.UEMessage{GNBRx: newGnbRx, GNBTx: newGnbTx, PrUeId: ue.GetPrUeId(), IsHandover: true}

	msg := context.UEMessage{GNBRx: newGnbRx, GNBTx: newGnbTx, GNBInboundChannel: newGnb.GetInboundChannel()}

	sender.SendMessageToUe(ue, msg)
	return nil
}

func HandlerPaging(gnb *context.GNBContext, message *ngapType.NGAPPDU) error {
	valueMessage := message.InitiatingMessage.Value.Paging

	var uEPagingIdentity *ngapType.UEPagingIdentity
	var tAIListForPaging *ngapType.TAIListForPaging

	for _, ies := range valueMessage.ProtocolIEs.List {
		switch ies.Id.Value {
		case ngapType.ProtocolIEIDUEPagingIdentity:

			if ies.Value.UEPagingIdentity == nil {
				return fmt.Errorf("ue paging identity is missing")
			}
			uEPagingIdentity = ies.Value.UEPagingIdentity

		case ngapType.ProtocolIEIDTAIListForPaging:

			if ies.Value.TAIListForPaging == nil {
				return fmt.Errorf("TAI List For Paging is missing")
			}
			tAIListForPaging = ies.Value.TAIListForPaging
		}
	}
	_ = tAIListForPaging

	gnb.AddPagedUE(uEPagingIdentity.FiveGSTMSI)

	logger.GnbLog.Info("Paging UE")
	return nil
}

func HandlerErrorIndication(gnb *context.GNBContext, message *ngapType.NGAPPDU) error {
	valueMessage := message.InitiatingMessage.Value.ErrorIndication

	var amfUeId, ranUeId int64

	for _, ies := range valueMessage.ProtocolIEs.List {
		switch ies.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:

			if ies.Value.AMFUENGAPID == nil {
				return fmt.Errorf("AMF UE ID is missing")
			}
			amfUeId = ies.Value.AMFUENGAPID.Value

		case ngapType.ProtocolIEIDRANUENGAPID:

			if ies.Value.RANUENGAPID == nil {
				return fmt.Errorf("RAN UE ID is missing")
			}
			ranUeId = ies.Value.RANUENGAPID.Value
		}
	}

	logger.GnbLog.Warn("Received an Error Indication for UE with AMF UE ID: ", amfUeId, " RAN UE ID: ", ranUeId)
	return nil
}

func getUeFromContext(gnb *context.GNBContext, ranUeId int64, amfUeId int64) *context.GNBUe {
	// check RanUeId and get UE.
	ue, err := gnb.GetGnbUe(ranUeId)
	if err != nil || ue == nil {
		logger.GnbLog.Error("RAN UE NGAP ID is incorrect, found: ", ranUeId)
		return nil
	}

	ue.SetAmfUeId(amfUeId)

	return ue
}

func causeToString(cause *ngapType.Cause) string {
	if cause != nil {
		switch cause.Present {
		case ngapType.CausePresentRadioNetwork:
			return "radioNetwork: " + causeRadioNetworkToString(cause.RadioNetwork)
		case ngapType.CausePresentTransport:
			return "transport: " + causeTransportToString(cause.Transport)
		case ngapType.CausePresentNas:
			return "nas: " + causeNasToString(cause.Nas)
		case ngapType.CausePresentProtocol:
			return "protocol: " + causeProtocolToString(cause.Protocol)
		case ngapType.CausePresentMisc:
			return "misc: " + causeMiscToString(cause.Misc)
		}
	}
	return "Cause not found"
}

func causeRadioNetworkToString(network *ngapType.CauseRadioNetwork) string {
	switch network.Value {
	case ngapType.CauseRadioNetworkPresentUnspecified:
		return "Unspecified cause for radio network"
	case ngapType.CauseRadioNetworkPresentTxnrelocoverallExpiry:
		return "Transfer the overall timeout of radio resources during handover"
	case ngapType.CauseRadioNetworkPresentSuccessfulHandover:
		return "Successful handover"
	case ngapType.CauseRadioNetworkPresentReleaseDueToNgranGeneratedReason:
		return "Release due to NG-RAN generated reason"
	case ngapType.CauseRadioNetworkPresentReleaseDueTo5gcGeneratedReason:
		return "Release due to 5GC generated reason"
	case ngapType.CauseRadioNetworkPresentHandoverCancelled:
		return "Handover cancelled"
	case ngapType.CauseRadioNetworkPresentPartialHandover:
		return "Partial handover"
	case ngapType.CauseRadioNetworkPresentHoFailureInTarget5GCNgranNodeOrTargetSystem:
		return "Handover failure in target 5GC NG-RAN node or target system"
	case ngapType.CauseRadioNetworkPresentHoTargetNotAllowed:
		return "Handover target not allowed"
	case ngapType.CauseRadioNetworkPresentTngrelocoverallExpiry:
		return "Transfer the overall timeout of radio resources during target NG-RAN relocation"
	case ngapType.CauseRadioNetworkPresentTngrelocprepExpiry:
		return "Transfer the preparation timeout of radio resources during target NG-RAN relocation"
	case ngapType.CauseRadioNetworkPresentCellNotAvailable:
		return "Cell not available"
	case ngapType.CauseRadioNetworkPresentUnknownTargetID:
		return "Unknown target ID"
	case ngapType.CauseRadioNetworkPresentNoRadioResourcesAvailableInTargetCell:
		return "No radio resources available in the target cell"
	case ngapType.CauseRadioNetworkPresentUnknownLocalUENGAPID:
		return "Unknown local UE NGAP ID"
	case ngapType.CauseRadioNetworkPresentInconsistentRemoteUENGAPID:
		return "Inconsistent remote UE NGAP ID"
	case ngapType.CauseRadioNetworkPresentHandoverDesirableForRadioReason:
		return "Handover desirable for radio reason"
	case ngapType.CauseRadioNetworkPresentTimeCriticalHandover:
		return "Time-critical handover"
	case ngapType.CauseRadioNetworkPresentResourceOptimisationHandover:
		return "Resource optimization handover"
	case ngapType.CauseRadioNetworkPresentReduceLoadInServingCell:
		return "Reduce load in serving cell"
	case ngapType.CauseRadioNetworkPresentUserInactivity:
		return "User inactivity"
	case ngapType.CauseRadioNetworkPresentRadioConnectionWithUeLost:
		return "Radio connection with UE lost"
	case ngapType.CauseRadioNetworkPresentRadioResourcesNotAvailable:
		return "Radio resources not available"
	case ngapType.CauseRadioNetworkPresentInvalidQosCombination:
		return "Invalid QoS combination"
	case ngapType.CauseRadioNetworkPresentFailureInRadioInterfaceProcedure:
		return "Failure in radio interface procedure"
	case ngapType.CauseRadioNetworkPresentInteractionWithOtherProcedure:
		return "Interaction with other procedure"
	case ngapType.CauseRadioNetworkPresentUnknownPDUSessionID:
		return "Unknown PDU session ID"
	case ngapType.CauseRadioNetworkPresentUnkownQosFlowID:
		return "Unknown QoS flow ID"
	case ngapType.CauseRadioNetworkPresentMultiplePDUSessionIDInstances:
		return "Multiple PDU session ID instances"
	case ngapType.CauseRadioNetworkPresentMultipleQosFlowIDInstances:
		return "Multiple QoS flow ID instances"
	case ngapType.CauseRadioNetworkPresentEncryptionAndOrIntegrityProtectionAlgorithmsNotSupported:
		return "Encryption and/or integrity protection algorithms not supported"
	case ngapType.CauseRadioNetworkPresentNgIntraSystemHandoverTriggered:
		return "NG intra-system handover triggered"
	case ngapType.CauseRadioNetworkPresentNgInterSystemHandoverTriggered:
		return "NG inter-system handover triggered"
	case ngapType.CauseRadioNetworkPresentXnHandoverTriggered:
		return "Xn handover triggered"
	case ngapType.CauseRadioNetworkPresentNotSupported5QIValue:
		return "Not supported 5QI value"
	case ngapType.CauseRadioNetworkPresentUeContextTransfer:
		return "UE context transfer"
	case ngapType.CauseRadioNetworkPresentImsVoiceEpsFallbackOrRatFallbackTriggered:
		return "IMS voice EPS fallback or RAT fallback triggered"
	case ngapType.CauseRadioNetworkPresentUpIntegrityProtectionNotPossible:
		return "UP integrity protection not possible"
	case ngapType.CauseRadioNetworkPresentUpConfidentialityProtectionNotPossible:
		return "UP confidentiality protection not possible"
	case ngapType.CauseRadioNetworkPresentSliceNotSupported:
		return "Slice not supported"
	case ngapType.CauseRadioNetworkPresentUeInRrcInactiveStateNotReachable:
		return "UE in RRC inactive state not reachable"
	case ngapType.CauseRadioNetworkPresentRedirection:
		return "Redirection"
	case ngapType.CauseRadioNetworkPresentResourcesNotAvailableForTheSlice:
		return "Resources not available for the slice"
	case ngapType.CauseRadioNetworkPresentUeMaxIntegrityProtectedDataRateReason:
		return "UE maximum integrity protected data rate reason"
	case ngapType.CauseRadioNetworkPresentReleaseDueToCnDetectedMobility:
		return "Release due to CN detected mobility"
	default:
		return "Unknown cause for radio network"
	}
}

func causeTransportToString(transport *ngapType.CauseTransport) string {
	switch transport.Value {
	case ngapType.CauseTransportPresentTransportResourceUnavailable:
		return "Transport resource unavailable"
	case ngapType.CauseTransportPresentUnspecified:
		return "Unspecified cause for transport"
	default:
		return "Unknown cause for transport"
	}
}

func causeNasToString(nas *ngapType.CauseNas) string {
	switch nas.Value {
	case ngapType.CauseNasPresentNormalRelease:
		return "Normal release"
	case ngapType.CauseNasPresentAuthenticationFailure:
		return "Authentication failure"
	case ngapType.CauseNasPresentDeregister:
		return "Deregister"
	case ngapType.CauseNasPresentUnspecified:
		return "Unspecified cause for NAS"
	default:
		return "Unknown cause for NAS"
	}
}

func causeProtocolToString(protocol *ngapType.CauseProtocol) string {
	switch protocol.Value {
	case ngapType.CauseProtocolPresentTransferSyntaxError:
		return "Transfer syntax error"
	case ngapType.CauseProtocolPresentAbstractSyntaxErrorReject:
		return "Abstract syntax error - Reject"
	case ngapType.CauseProtocolPresentAbstractSyntaxErrorIgnoreAndNotify:
		return "Abstract syntax error - Ignore and notify"
	case ngapType.CauseProtocolPresentMessageNotCompatibleWithReceiverState:
		return "Message not compatible with receiver state"
	case ngapType.CauseProtocolPresentSemanticError:
		return "Semantic error"
	case ngapType.CauseProtocolPresentAbstractSyntaxErrorFalselyConstructedMessage:
		return "Abstract syntax error - Falsely constructed message"
	case ngapType.CauseProtocolPresentUnspecified:
		return "Unspecified cause for protocol"
	default:
		return "Unknown cause for protocol"
	}
}

func causeMiscToString(misc *ngapType.CauseMisc) string {
	switch misc.Value {
	case ngapType.CauseMiscPresentControlProcessingOverload:
		return "Control processing overload"
	case ngapType.CauseMiscPresentNotEnoughUserPlaneProcessingResources:
		return "Not enough user plane processing resources"
	case ngapType.CauseMiscPresentHardwareFailure:
		return "Hardware failure"
	case ngapType.CauseMiscPresentOmIntervention:
		return "OM (Operations and Maintenance) intervention"
	case ngapType.CauseMiscPresentUnknownPLMN:
		return "Unknown PLMN (Public Land Mobile Network)"
	case ngapType.CauseMiscPresentUnspecified:
		return "Unspecified cause for miscellaneous"
	default:
		return "Unknown cause for miscellaneous"
	}
}
