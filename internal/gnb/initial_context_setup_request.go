package gnb

import (
	"fmt"

	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/free5gc/ngap/ngapType"
	"go.uber.org/zap"
)

func handleInitialContextSetupRequest(gnb *GnodeB, initialContextSetupRequest *ngapType.InitialContextSetupRequest) error {
	var (
		amfueNGAPID *ngapType.AMFUENGAPID
		ranueNGAPID *ngapType.RANUENGAPID
		// protocolIEIDPDUSessionResourceSetupListCxtReq *ngapType.PDUSessionResourceSetupListCxtReq
		nasPDU *ngapType.NASPDU
	)

	for _, ie := range initialContextSetupRequest.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			amfueNGAPID = ie.Value.AMFUENGAPID
		case ngapType.ProtocolIEIDRANUENGAPID:
			ranueNGAPID = ie.Value.RANUENGAPID
		case ngapType.ProtocolIEIDPDUSessionResourceSetupListCxtReq:
			// protocolIEIDPDUSessionResourceSetupListCxtReq = ie.Value.PDUSessionResourceSetupListCxtReq
		case ngapType.ProtocolIEIDNASPDU:
			nasPDU = ie.Value.NASPDU
		}
	}

	logger.GnbLogger.Debug("Received InitialContextSetupRequest",
		zap.Int64("AMFUENGAPID", amfueNGAPID.Value),
		zap.Int64("RANUENGAPID", ranueNGAPID.Value),
	)

	err := gnb.SendInitialContextSetupResponse(&InitialContextSetupResponseOpts{
		AMFUENGAPID: amfueNGAPID.Value,
		RANUENGAPID: ranueNGAPID.Value,
	})
	if err != nil {
		return fmt.Errorf("could not send InitialContextSetupResponse: %v", err)
	}

	logger.Logger.Debug(
		"Sent Initial Context Setup Response",
	)

	ue, err := loadUE(gnb, ranueNGAPID.Value)
	if err != nil {
		return fmt.Errorf("cannot find UE for DownlinkNASTransport message: %v", err)
	}

	err = ue.SendDownlinkNAS(nasPDU.Value, amfueNGAPID.Value, ranueNGAPID.Value)
	if err != nil {
		return fmt.Errorf("HandleDownlinkNASTransport failed: %v", err)
	}

	return nil
}
