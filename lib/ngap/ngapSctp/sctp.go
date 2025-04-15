package ngapSctp

import (
	"encoding/binary"
	"unsafe"
)

var clientNum int
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
