/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 */
package sender

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/ishidawataru/sctp"
)

var NGAP_PPID uint32 = 60

func init() {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	// little endian
	case [2]byte{0xCD, 0xAB}:
		tmp := make([]byte, 4)
		binary.BigEndian.PutUint32(tmp, NGAP_PPID)
		NGAP_PPID = binary.LittleEndian.Uint32(tmp)
	// big endian
	case [2]byte{0xAB, 0xCD}:
	}
}

func SendToAmF(message []byte, conn *sctp.SCTPConn) error {
	info := &sctp.SndRcvInfo{
		Stream: uint16(0),
		PPID:   NGAP_PPID,
	}

	_, err := conn.SCTPWrite(message, info)
	if err != nil {
		return fmt.Errorf("error sending NGAP message %w", err)
	}

	return nil
}
