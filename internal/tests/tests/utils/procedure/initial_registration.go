package procedure

import (
	"fmt"
	"time"

	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
)

const timeoutPerMessage = 1 * time.Second

type InitialRegistrationOpts struct {
	RANUENGAPID int64
	UE          *ue.UE
}

func InitialRegistration(opts *InitialRegistrationOpts) error {
	err := opts.UE.SendRegistrationRequest(opts.RANUENGAPID, nasMessage.RegistrationType5GSInitialRegistration)
	if err != nil {
		return fmt.Errorf("could not build Registration Request NAS PDU: %v", err)
	}

	_, err = opts.UE.WaitForNASGMMMessage(nas.MsgTypeRegistrationAccept, timeoutPerMessage)
	if err != nil {
		return fmt.Errorf("could not receive Registration Accept for periodic update: %v", err)
	}

	_, err = opts.UE.WaitForNASGSMMessage(nas.MsgTypePDUSessionEstablishmentAccept, timeoutPerMessage)
	if err != nil {
		return fmt.Errorf("timeout waiting for PDU session establishment accept: %v", err)
	}

	_, err = opts.UE.WaitForPDUSession(timeoutPerMessage)
	if err != nil {
		return fmt.Errorf("timeout waiting for PDU session: %v", err)
	}

	return nil
}
