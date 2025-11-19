package ue

import (
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/free5gc/nas"
	"go.uber.org/zap"
)

func handleRegistrationReject(ue *UE, _ *nas.Message) error {
	logger.UeLogger.Debug("Received Registration Reject NAS message", zap.String("IMSI", ue.UeSecurity.Supi))
	return nil
}
