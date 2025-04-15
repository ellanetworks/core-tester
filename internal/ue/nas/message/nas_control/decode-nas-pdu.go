/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */
package nas_control

import (
	"fmt"

	"github.com/free5gc/nas"
)

func GetNasPduFromPduAccept(dlNas *nas.Message) (*nas.Message, error) {
	payload := dlNas.DLNASTransport.GetPayloadContainerContents()
	m := new(nas.Message)
	err := m.PlainNasDecode(&payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode NAS PDU: %v", err)
	}
	return m, nil
}
