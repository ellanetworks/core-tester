/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */
package nas_control

import (
	"github.com/free5gc/nas"
)

func GetNasPduFromPduAccept(dlNas *nas.Message) (m *nas.Message) {
	// get payload container from DL NAS.
	payload := dlNas.DLNASTransport.GetPayloadContainerContents()
	m = new(nas.Message)
	err := m.PlainNasDecode(&payload)
	if err != nil {
		return nil
	}
	return
}
