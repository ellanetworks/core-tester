package ue

import (
	"encoding/binary"
	"fmt"
)

// ---- QFD constants (TS 24.501 §9.11.4.12) ----
const (
	qfdParamID5QI    uint8 = 0x01
	qfdParamIDGfbrUl uint8 = 0x02
	qfdParamIDGfbrDl uint8 = 0x03
	qfdParamIDMfbrUl uint8 = 0x04
	qfdParamIDMfbrDl uint8 = 0x05
	qfdParamIDAvgWnd uint8 = 0x06
	qfdParamIDEpsBId uint8 = 0x07
)

const (
	qfdQfiBitmask uint8 = 0x3f // bits 6..1
	qfdEbit       uint8 = 0x40 // bit 6 in the NumOfParam octet
)

const qfdFixLen uint8 = 0x03

// Unit codes used in rate params
const (
	qfRateUnit1Kbps uint8 = 0x01
	qfRateUnit1Mbps uint8 = 0x06
	qfRateUnit1Gbps uint8 = 0x0B
)

type qosFlowParameter struct {
	ParamID  uint8
	ParamLen uint8

	FiveQI      *uint8
	GfbrUlKbps  *uint64
	GfbrDlKbps  *uint64
	MfbrUlKbps  *uint64
	MfbrDlKbps  *uint64
	AvgWindowMs *uint16
	EpsBearerID *uint8
}

type qoSFlowDescription struct {
	ParamList  []qosFlowParameter
	Qfi        uint8
	OpCode     uint8
	EBit       bool
	ParamCount uint8
	QFDLen     uint8
}

func parseAuthorizedQosFlowDescriptions(content []byte) ([]qoSFlowDescription, error) { //nolint:gocognit
	var descs []qoSFlowDescription

	i := 0

	for i < len(content) {
		if len(content[i:]) < 3 {
			return nil, fmt.Errorf("qfd: truncated header at off=%d (have %d, need 3)", i, len(content[i:]))
		}

		var d qoSFlowDescription

		d.QFDLen = qfdFixLen

		// QFI (mask to bits 6..1)
		d.Qfi = content[i] & qfdQfiBitmask
		i++

		// OpCode
		op := content[i]
		d.OpCode = op
		i++

		// NumOfParam: E-bit + count(6 bits)
		num := content[i]
		i++
		d.EBit = (num & qfdEbit) != 0
		d.ParamCount = num & 0x3F

		// Parameters
		d.ParamList = make([]qosFlowParameter, 0, int(d.ParamCount))
		for p := 0; p < int(d.ParamCount); p++ {
			if len(content[i:]) < 2 {
				return nil, fmt.Errorf("qfd: truncated parameter header at off=%d", i)
			}

			pid := content[i]
			plen := content[i+1]
			i += 2

			if len(content[i:]) < int(plen) {
				return nil, fmt.Errorf("qfd: truncated parameter content at off=%d want=%d have=%d", i, plen, len(content[i:]))
			}

			raw := make([]byte, plen)
			copy(raw, content[i:i+int(plen)])
			i += int(plen)

			param := qosFlowParameter{
				ParamID:  pid,
				ParamLen: plen,
			}

			switch pid {
			case qfdParamID5QI:
				if plen != 1 {
					break
				}

				v := raw[0]
				param.FiveQI = &v

			case qfdParamIDGfbrUl, qfdParamIDGfbrDl, qfdParamIDMfbrUl, qfdParamIDMfbrDl:
				if plen != 3 {
					break
				}

				unit := raw[0]
				val := binary.BigEndian.Uint16(raw[1:3])

				if kbps, ok := toKbps(unit, val); ok {
					switch pid {
					case qfdParamIDGfbrUl:
						param.GfbrUlKbps = &kbps
					case qfdParamIDGfbrDl:
						param.GfbrDlKbps = &kbps
					case qfdParamIDMfbrUl:
						param.MfbrUlKbps = &kbps
					case qfdParamIDMfbrDl:
						param.MfbrDlKbps = &kbps
					}
				}

			case qfdParamIDAvgWnd:
				if plen != 2 {
					break
				}

				ms := binary.BigEndian.Uint16(raw)
				param.AvgWindowMs = &ms

			case qfdParamIDEpsBId:
				if plen != 1 {
					break
				}

				ebi := raw[0]
				param.EpsBearerID = &ebi
			}

			d.QFDLen += 2 + plen
			d.ParamList = append(d.ParamList, param)
		}

		descs = append(descs, d)
	}

	return descs, nil
}

func toKbps(unit uint8, v uint16) (kbps uint64, ok bool) {
	switch unit {
	case qfRateUnit1Kbps:
		return uint64(v), true
	case qfRateUnit1Mbps:
		return uint64(v) * 1000, true
	case qfRateUnit1Gbps:
		return uint64(v) * 1000 * 1000, true
	default:
		return 0, false
	}
}
