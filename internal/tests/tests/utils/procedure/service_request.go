package procedure

import (
	"context"
	"fmt"

	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/ellanetworks/core-tester/internal/tests/tests/utils/validate"
	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/ngap/ngapType"
	"go.uber.org/zap"
)

type ServiceRequestOpts struct {
	Mcc              string
	Mnc              string
	PDUSessionStatus [16]bool
	Tac              string
	GNBID            string
	SST              int32
	SD               string
	AMFUENGAPID      int64
	RANUENGAPID      int64
	UE               *ue.UE
	GnodeB           *gnb.GnodeB
}

type ServiceRequestResp struct {
	ULTEID     uint32
	UPFAddress string
}

func ServiceRequest(ctx context.Context, opts *ServiceRequestOpts) (*ServiceRequestResp, error) {
	serviceRequest, err := ue.BuildServiceRequest(&ue.ServiceRequestOpts{
		ServiceType:      nasMessage.ServiceTypeData,
		AMFSetID:         opts.UE.GetAmfSetId(),
		AMFPointer:       opts.UE.GetAmfPointer(),
		TMSI5G:           opts.UE.GetTMSI5G(),
		PDUSessionStatus: &opts.PDUSessionStatus,
		UESecurity:       opts.UE.UeSecurity,
	})
	if err != nil {
		return nil, fmt.Errorf("could not build Service Request NAS PDU: %v", err)
	}

	encodedPdu, err := opts.UE.EncodeNasPduWithSecurity(serviceRequest, nas.SecurityHeaderTypeIntegrityProtected)
	if err != nil {
		return nil, fmt.Errorf("error encoding %s IMSI UE  NAS Security Mode Complete message: %v", opts.UE.UeSecurity.Supi, err)
	}

	err = opts.GnodeB.SendInitialUEMessage(&gnb.InitialUEMessageOpts{
		Mcc:                   opts.Mcc,
		Mnc:                   opts.Mnc,
		GnbID:                 opts.GNBID,
		Tac:                   opts.Tac,
		RanUENGAPID:           opts.RANUENGAPID,
		NasPDU:                encodedPdu,
		Guti5g:                opts.UE.UeSecurity.Guti,
		RRCEstablishmentCause: ngapType.RRCEstablishmentCausePresentMoData,
	})
	if err != nil {
		return nil, fmt.Errorf("could not send InitialUEMessage: %v", err)
	}

	logger.Logger.Debug(
		"Sent Initial UE Message for Service Request",
		zap.String("IMSI", opts.UE.UeSecurity.Supi),
		zap.Int64("RAN UE NGAP ID", opts.RANUENGAPID),
	)

	fr, err := opts.GnodeB.ReceiveFrame(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	initialContextSetupReq, err := validate.InitialContextSetupRequest(&validate.InitialContextSetupRequestOpts{
		Frame: fr,
	})
	if err != nil {
		return nil, fmt.Errorf("InitialContextSetupRequest validation failed: %v", err)
	}

	if initialContextSetupReq.PDUSessionResourceSetupListCxtReq == nil {
		return nil, fmt.Errorf("PDUSessionResourceSetupListCxtReq is nil in Initial Context Setup Request")
	}

	rsp, err := validate.PDUSessionResourceSetupListCxtReq(initialContextSetupReq.PDUSessionResourceSetupListCxtReq, 1, opts.SST, opts.SD)
	if err != nil {
		return nil, fmt.Errorf("PDUSessionResourceSetupListCxtReq validation failed: %v", err)
	}

	logger.Logger.Debug(
		"Validated PDUSessionResourceSetupListCxtReq in Initial Context Setup Request for Service Request",
		zap.String("IMSI", opts.UE.UeSecurity.Supi),
		zap.Int64("RAN UE NGAP ID", opts.RANUENGAPID),
		zap.Uint32("ULTEID", rsp.PDUSessionResourceSetupRequestTransfer.ULTeid),
		zap.String("UPFAddress", rsp.PDUSessionResourceSetupRequestTransfer.UpfAddress),
	)

	logger.Logger.Debug(
		"Received Initial Context Setup Request for Service Request",
		zap.String("IMSI", opts.UE.UeSecurity.Supi),
		zap.Int64("RAN UE NGAP ID", opts.RANUENGAPID),
	)

	err = opts.GnodeB.SendInitialContextSetupResponse(&gnb.InitialContextSetupResponseOpts{
		AMFUENGAPID: opts.AMFUENGAPID,
		RANUENGAPID: opts.RANUENGAPID,
	})
	if err != nil {
		return nil, fmt.Errorf("could not send InitialContextSetupResponse: %v", err)
	}

	logger.Logger.Debug(
		"Sent Initial Context Setup Response for Service Request",
		zap.String("IMSI", opts.UE.UeSecurity.Supi),
		zap.Int64("RAN UE NGAP ID", opts.RANUENGAPID),
	)

	return &ServiceRequestResp{
		ULTEID:     rsp.PDUSessionResourceSetupRequestTransfer.ULTeid,
		UPFAddress: rsp.PDUSessionResourceSetupRequestTransfer.UpfAddress,
	}, nil
}
