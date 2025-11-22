package procedure

import (
	"fmt"
	"time"

	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/free5gc/nas"
	"github.com/free5gc/ngap/ngapType"
)

type ServiceRequestOpts struct {
	PDUSessionStatus [16]bool
	RANUENGAPID      int64
	UE               *ue.UE
	GnodeB           *gnb.GnodeB
}

func ServiceRequest(opts *ServiceRequestOpts) error {
	err := opts.UE.SendServiceRequest(opts.RANUENGAPID, opts.PDUSessionStatus)
	if err != nil {
		return fmt.Errorf("could not send Service Request NAS message: %v", err)
	}

	_, err = opts.GnodeB.WaitForMessage(ngapType.NGAPPDUPresentInitiatingMessage, ngapType.InitiatingMessagePresentInitialContextSetupRequest, 500*time.Millisecond)
	if err != nil {
		return fmt.Errorf("could not receive SCTP frame: %v", err)
	}

	_, err = opts.UE.WaitForNASGMMMessage(nas.MsgTypeServiceAccept, 500*time.Millisecond)
	if err != nil {
		return fmt.Errorf("could not receive Service Accept NAS message: %v", err)
	}

	return nil
}
