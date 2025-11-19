package procedure

import (
	"fmt"
	"time"

	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/ngap/ngapType"
)

const timeoutPerMessage = 1 * time.Second

type InitialRegistrationOpts struct {
	RANUENGAPID int64
	UE          *ue.UE
	GnodeB      *gnb.GnodeB
}

func InitialRegistration(opts *InitialRegistrationOpts) error {
	err := opts.UE.SendRegistrationRequest(opts.RANUENGAPID, nasMessage.RegistrationType5GSInitialRegistration)
	if err != nil {
		return fmt.Errorf("could not build Registration Request NAS PDU: %v", err)
	}

	_, err = opts.GnodeB.WaitForMessage(ngapType.NGAPPDUPresentInitiatingMessage, ngapType.InitiatingMessagePresentDownlinkNASTransport, timeoutPerMessage)
	if err != nil {
		return fmt.Errorf("could not find downlink NAS transport message ba: %v", err)
	}

	_, err = opts.GnodeB.WaitForMessage(ngapType.NGAPPDUPresentInitiatingMessage, ngapType.InitiatingMessagePresentDownlinkNASTransport, timeoutPerMessage)
	if err != nil {
		return fmt.Errorf("could not find downlink NAS transport message 2: %v", err)
	}

	_, err = opts.GnodeB.WaitForMessage(ngapType.NGAPPDUPresentInitiatingMessage, ngapType.InitiatingMessagePresentInitialContextSetupRequest, timeoutPerMessage)
	if err != nil {
		return fmt.Errorf("could not find initial context setup request message: %v", err)
	}

	_, err = opts.GnodeB.WaitForMessage(ngapType.NGAPPDUPresentInitiatingMessage, ngapType.InitiatingMessagePresentPDUSessionResourceSetupRequest, timeoutPerMessage)
	if err != nil {
		return fmt.Errorf("could not find PDU session resource setup request message: %v", err)
	}

	_, err = opts.UE.WaitForPDUSession(timeoutPerMessage)
	if err != nil {
		return fmt.Errorf("timeout waiting for PDU session: %v", err)
	}

	return nil
}
