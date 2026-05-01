package ue

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasConvert"
	"github.com/free5gc/nas/nasMessage"
)

type PduAddressInfo struct {
	IP             netip.Addr
	IPV6           netip.Addr
	PDUSessionType uint8
}

// parsePduAddressInformation decodes the PDU address per TS 24.501 section 9.11.4.10.
//
// Table 9.11.4.10.1 defines the PDU address information element structure:
//
//	Octet 3: PDU session type value (bits 1-3) + SI6LLA bit (bit 4) + spare bits
//	Octet 4-11: IPv6 interface identifier (for IPv6 or IPv4v6)
//	Octet 12-15: IPv4 address (for IPv4 or IPv4v6)
//
// The addrInfo slice (from GetPDUAddressInformation()) contains 12 bytes:
// - For IPv4: octets 4-7 (IPv4 address) + 4 spare bytes
// - For IPv6: octets 4-11 (IPv6 interface identifier)
// - For IPv4v6: octets 4-11 (IPv6 interface identifier) + octets 12-15 (IPv4 address)
func parsePduAddressInformation(addrInfo [12]uint8, pduSessionType uint8) (PduAddressInfo, error) {
	info := PduAddressInfo{
		PDUSessionType: pduSessionType,
	}

	switch pduSessionType {
	case nasMessage.PDUSessionTypeIPv4:
		ueIPString := fmt.Sprintf("%d.%d.%d.%d", addrInfo[0], addrInfo[1], addrInfo[2], addrInfo[3])

		ueIP, err := netip.ParseAddr(ueIPString)
		if err != nil {
			return PduAddressInfo{}, fmt.Errorf("could not parse IPv4 address from NAS: %v", err)
		}

		info.IP = ueIP

	case nasMessage.PDUSessionTypeIPv6:
		var ifaceId [8]uint8
		copy(ifaceId[:], addrInfo[0:8])
		info.IPV6 = interfaceIdToLinkLocal(ifaceId)

	case nasMessage.PDUSessionTypeIPv4IPv6:
		var ifaceId [8]uint8
		copy(ifaceId[:], addrInfo[0:8])
		info.IPV6 = interfaceIdToLinkLocal(ifaceId)

		ueIPString := fmt.Sprintf("%d.%d.%d.%d", addrInfo[8], addrInfo[9], addrInfo[10], addrInfo[11])

		ueIP, err := netip.ParseAddr(ueIPString)
		if err != nil {
			return PduAddressInfo{}, fmt.Errorf("could not parse IPv4 address from NAS: %v", err)
		}

		info.IP = ueIP
	}

	return info, nil
}

func interfaceIdToLinkLocal(interfaceId [8]uint8) netip.Addr {
	linkLocalPrefix := [8]uint8{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	var addr [16]byte
	copy(addr[0:8], linkLocalPrefix[:])
	copy(addr[8:16], interfaceId[:])

	return netip.AddrFrom16(addr)
}

func getNasPduFromDLNASTransport(dlNas *nas.Message) (*nas.Message, error) {
	payload := dlNas.DLNASTransport.GetPayloadContainerContents()
	m := new(nas.Message)

	err := m.PlainNasDecode(&payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode NAS PDU: %v", err)
	}

	return m, nil
}

func mtuFromExtendProtocolConfigurationOptionsContents(pco_buf []byte) (uint16, error) {
	pco := nasConvert.NewProtocolConfigurationOptions()

	err := pco.UnMarshal(pco_buf)
	if err != nil {
		return 0, fmt.Errorf("could not decode Extended Protocol Configuration Options: %v", err)
	}

	for _, o := range pco.ProtocolOrContainerList {
		switch o.ProtocolOrContainerID {
		case nasMessage.IPv4LinkMTUDL:
			return binary.BigEndian.Uint16(o.Contents), nil
		default:
			continue
		}
	}

	return 0, nil
}
