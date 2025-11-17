package handlers

import (
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/free5gc/ngap/ngapType"
)

func handleNGResetAcknowledge(_ *ngapType.NGResetAcknowledge) error {
	logger.Logger.Debug("Received NGResetAcknowledge")

	return nil
}
