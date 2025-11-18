package procedure

import (
	"context"
	"fmt"
	"time"

	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/ellanetworks/core-tester/internal/tests/tests/utils/validate"
	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/free5gc/ngap/ngapType"
	"go.uber.org/zap"
)

type ServiceRequestOpts struct {
	PDUSessionStatus [16]bool
	SST              int32
	SD               string
	RANUENGAPID      int64
	UE               *ue.UE
	GnodeB           *gnb.GnodeB
}

type ServiceRequestResp struct {
	ULTEID     uint32
	UPFAddress string
}

func ServiceRequest(ctx context.Context, opts *ServiceRequestOpts) (*ServiceRequestResp, error) {
	err := opts.UE.SendServiceRequest(opts.RANUENGAPID, opts.PDUSessionStatus)
	if err != nil {
		return nil, fmt.Errorf("could not send Service Request NAS message: %v", err)
	}

	fr, err := opts.GnodeB.WaitForMessage(ngapType.NGAPPDUPresentInitiatingMessage, ngapType.InitiatingMessagePresentInitialContextSetupRequest, 500*time.Millisecond)
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

	return &ServiceRequestResp{
		ULTEID:     rsp.PDUSessionResourceSetupRequestTransfer.ULTeid,
		UPFAddress: rsp.PDUSessionResourceSetupRequestTransfer.UpfAddress,
	}, nil
}
