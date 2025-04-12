/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */
package nas

import (
	"github.com/ellanetworks/core-tester/internal/gnb/context"
	"github.com/ellanetworks/core-tester/internal/gnb/nas/handler"
)

func Dispatch(ue *context.GNBUe, message []byte, gnb *context.GNBContext) {

	switch ue.GetState() {

	case context.Initialized:
		// handler UE message.
		handler.HandlerUeInitialized(ue, message, gnb)

	case context.Ongoing:
		// handler UE message.
		handler.HandlerUeOngoing(ue, message, gnb)

	case context.Ready:
		// handler UE message.
		handler.HandlerUeReady(ue, message, gnb)
	}
}
