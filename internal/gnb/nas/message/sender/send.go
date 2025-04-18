/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */
package sender

import (
	"github.com/ellanetworks/core-tester/internal/gnb/context"
	"github.com/ellanetworks/core-tester/internal/logger"
)

func SendToUe(ue *context.GNBUe, message []byte) {
	ue.Lock()
	gnbTx := ue.GetGnbTx()
	if gnbTx == nil {
		logger.GnbLog.Warnf("do not send NAS messages to UE as channel is closed")
	} else {
		gnbTx <- context.UEMessage{IsNas: true, Nas: message}
	}
	ue.Unlock()
}

func SendMessageToUe(ue *context.GNBUe, message context.UEMessage) {
	ue.Lock()
	gnbTx := ue.GetGnbTx()
	if gnbTx == nil {
		logger.GnbLog.Warnf("do not send NAS messages to UE as channel is closed")
	} else {
		gnbTx <- message
	}
	ue.Unlock()
}
