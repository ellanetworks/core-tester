/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */
package state

import (
	"github.com/ellanetworks/core-tester/internal/ue/context"
	"github.com/ellanetworks/core-tester/internal/ue/nas"
)

func DispatchState(ue *context.UEContext, message []byte) {
	nas.DispatchNas(ue, message)
}
