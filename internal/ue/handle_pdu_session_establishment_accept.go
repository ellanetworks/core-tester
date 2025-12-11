package ue

import (
	"fmt"

	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/ellanetworks/core-tester/internal/tests/tests/utils"
	"github.com/free5gc/nas/nasMessage"
	"go.uber.org/zap"
)

func handlePDUSessionEstablishmentAccept(ue *UE, msg *nasMessage.PDUSessionEstablishmentAccept) error {
	ueIP, err := utils.UEIPFromNAS(msg.GetPDUAddressInformation())
	if err != nil {
		return fmt.Errorf("could not get UE IP from NAS PDU Address Information: %v", err)
	}

	pco_buf := msg.GetExtendedProtocolConfigurationOptionsContents()

	mtu, err := utils.MTUFromExtendProtocolConfigurationOptionsContents(pco_buf)
	if err != nil {
		return fmt.Errorf("could not get MTU from Extended Protocol Configuration Options: %v", err)
	}

	logger.UeLogger.Debug(
		"Received PDU Session Establishment Accept NAS message",
		zap.String("IMSI", ue.UeSecurity.Supi),
		zap.Uint8("PDU Session ID", msg.GetPDUSessionID()),
		zap.String("UE IP", ueIP.String()),
		zap.Uint16("MTU", mtu),
	)

	ue.SetPDUSession(PDUSessionInfo{
		PDUSessionID: msg.GetPDUSessionID(),
		UEIP:         ueIP.String(),
		MTU:          mtu,
	})

	return nil
}
