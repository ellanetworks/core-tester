package gnb

import (
	"fmt"

	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/free5gc/ngap/ngapType"
	"go.uber.org/zap"
)

func handlePDUSessionResourceSetupRequest(gnb *GnodeB, pDUSessionResourceSetupRequest *ngapType.PDUSessionResourceSetupRequest) error {
	var (
		amfueNGAPID *ngapType.AMFUENGAPID
		ranueNGAPID *ngapType.RANUENGAPID
	)

	for _, ie := range pDUSessionResourceSetupRequest.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			amfueNGAPID = ie.Value.AMFUENGAPID
		case ngapType.ProtocolIEIDRANUENGAPID:
			ranueNGAPID = ie.Value.RANUENGAPID
		}
	}

	logger.Logger.Debug(
		"Received PDU Session Resource Setup Request",
		zap.String("GNB ID", gnb.GnbID),
		zap.Int64("RAN UE NGAP ID", ranueNGAPID.Value),
		zap.Int64("AMF UE NGAP ID", amfueNGAPID.Value),
		// zap.Uint8("PDU Session ID", opts.PDUSessionID),
		// zap.String("UE IP", resp.PDUSessionResourceSetupListValue.UEIP.String()),
		// zap.String("UPF Address", resp.PDUSessionResourceSetupListValue.PDUSessionResourceSetupRequestTransfer.UpfAddress),
		// zap.Uint32("UL TEID", resp.PDUSessionResourceSetupListValue.PDUSessionResourceSetupRequestTransfer.ULTeid),
	)

	err := gnb.SendPDUSessionResourceSetupResponse(&PDUSessionResourceSetupResponseOpts{
		AMFUENGAPID: amfueNGAPID.Value,
		RANUENGAPID: ranueNGAPID.Value,
		N3GnbIp:     gnb.N3Address,
		PDUSessions: [16]*GnbPDUSession{
			{
				PDUSessionId: gnb.PDUSessionID,
				DownlinkTeid: gnb.DownlinkTEID,
				QFI:          1,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to send PDUSessionResourceSetupResponse: %v", err)
	}

	logger.Logger.Debug(
		"Sent PDUSession Resource Setup Response",
		zap.String("GNB ID", gnb.GnbID),
		zap.Int64("RAN UE NGAP ID", ranueNGAPID.Value),
		zap.Int64("AMF UE NGAP ID", amfueNGAPID.Value),
		zap.Int64("PDU Session ID", gnb.PDUSessionID),
		zap.Uint32("Downlink TEID", gnb.DownlinkTEID),
	)

	return nil
}
