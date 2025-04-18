/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */
package sender

import (
	context2 "github.com/ellanetworks/core-tester/internal/gnb/context"
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/ellanetworks/core-tester/internal/ue/context"
)

func SendToGnb(ue *context.UEContext, message []byte) {
	SendToGnbMsg(ue, context2.UEMessage{IsNas: true, Nas: message})
}

func SendToGnbMsg(ue *context.UEContext, message context2.UEMessage) {
	ue.Lock()
	gnbRx := ue.GetGnbRx()
	if gnbRx == nil {
		logger.UELog.Warn("do not send NAS messages to gNB as channel is closed")
	} else {
		gnbRx <- message
	}
	ue.Unlock()
}
