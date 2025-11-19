package ue

import (
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/free5gc/nas"
	"go.uber.org/zap"
)

func handleRegistrationReject(ue *UE, msg *nas.Message) error {
	cause := msg.RegistrationReject.GetCauseValue()

	logger.UeLogger.Debug(
		"Received Registration Reject NAS message",
		zap.String("IMSI", ue.UeSecurity.Supi),
		zap.String("Cause", cause5GMMToString(cause)),
	)

	return nil
}
