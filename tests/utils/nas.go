package utils

import (
	"fmt"
	"net"

	"github.com/free5gc/nas"
	"github.com/free5gc/ngap/ngapType"
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

func GetNASPDUFromDownlinkNasTransport(downlinkNASTransport *ngapType.DownlinkNASTransport) *ngapType.NASPDU {
	for _, ie := range downlinkNASTransport.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDNASPDU:
			return ie.Value.NASPDU
		default:
			continue
		}
	}

	return nil
}

func GetNASPDUFromInitialContextSetupRequest(initialContextSetupRequest *ngapType.InitialContextSetupRequest) *ngapType.NASPDU {
	for _, ie := range initialContextSetupRequest.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDNASPDU:
			return ie.Value.NASPDU
		default:
			continue
		}
	}

	return nil
}

func GetAMFUENGAPIDFromDownlinkNASTransport(downlinkNASTransport *ngapType.DownlinkNASTransport) *ngapType.AMFUENGAPID {
	for _, ie := range downlinkNASTransport.ProtocolIEs.List {
		switch ie.Id.Value {
		case ngapType.ProtocolIEIDAMFUENGAPID:
			return ie.Value.AMFUENGAPID
		default:
			continue
		}
	}

	return nil
}

func UEIPFromNAS(ip [12]uint8) (*net.IP, error) {
	ueIPString := fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])

	ueIP := net.ParseIP(ueIPString)
	if ueIP == nil {
		return nil, fmt.Errorf("could not parse UE IP: %s", ueIPString)
	}

	return &ueIP, nil
}

func SDFromNAS(sd [3]uint8) string {
	return fmt.Sprintf("%x%x%x", sd[0], sd[1], sd[2])
}
