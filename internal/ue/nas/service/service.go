/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */

// Package service
package service

import (
	gnbContext "github.com/ellanetworks/core-tester/internal/gnb/context"
	"github.com/ellanetworks/core-tester/internal/ue/context"
)

func InitConn(ue *context.UEContext, gnbInboundChannel chan gnbContext.UEMessage) {
	ue.SetGnbRx(make(chan gnbContext.UEMessage, 1))
	ue.SetGnbTx(make(chan gnbContext.UEMessage, 1))

	// Send channels to gNB
	gnbInboundChannel <- gnbContext.UEMessage{GNBTx: ue.GetGnbTx(), GNBRx: ue.GetGnbRx(), PrUeId: ue.GetPrUeId(), Tmsi: ue.Get5gGuti()}
	msg := <-ue.GetGnbTx()
	ue.SetAmfMccAndMnc(msg.Mcc, msg.Mnc)
}
