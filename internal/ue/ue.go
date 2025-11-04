package ue

import (
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/ellanetworks/core-tester/internal/common/sidf"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/nas/security"
	"github.com/free5gc/openapi/models"
)

const (
	MM5G_NULL                 = 0x00
	MM5G_DEREGISTERED         = 0x01
	MM5G_REGISTERED_INITIATED = 0x02
	MM5G_REGISTERED           = 0x03
	MM5G_SERVICE_REQ_INIT     = 0x04
	MM5G_DEREGISTERED_INIT    = 0x05
	MM5G_IDLE                 = 0x06
)

type UESecurity struct {
	Supi                 string
	Msin                 string
	mcc                  string
	mnc                  string
	ULCount              security.Count
	DLCount              security.Count
	UeSecurityCapability *nasType.UESecurityCapability
	IntegrityAlg         uint8
	CipheringAlg         uint8
	NgKsi                models.NgKsi
	Snn                  string
	KnasEnc              [16]uint8
	KnasInt              [16]uint8
	Kamf                 []uint8
	AuthenticationSubs   models.AuthenticationSubscription
	Suci                 nasType.MobileIdentity5GS
	suciPublicKey        sidf.HomeNetworkPublicKey
	RoutingIndicator     string
	Guti                 *nasType.GUTI5G
}

type UE struct {
	UeSecurity UESecurity
	StateMM    int
	Dnn        string
	Snssai     models.Snssai
}

type UEOpts struct {
	Msin                 string
	UeSecurityCapability *nasType.UESecurityCapability
	K                    string
	OpC                  string
	Amf                  string
	Sqn                  string
	Mcc                  string
	Mnc                  string
	HomeNetworkPublicKey sidf.HomeNetworkPublicKey
	RoutingIndicator     string
	Dnn                  string
	Sst                  int32
	Sd                   string
}

func NewUE(opts *UEOpts) (*UE, error) {
	ue := UE{}

	ue.UeSecurity.Msin = opts.Msin
	ue.UeSecurity.UeSecurityCapability = opts.UeSecurityCapability

	integAlg, cipherAlg, err := SelectAlgorithms(ue.UeSecurity.UeSecurityCapability)
	if err != nil {
		return nil, fmt.Errorf("could not select security algorithms: %v", err)
	}

	ue.UeSecurity.IntegrityAlg = integAlg
	ue.UeSecurity.CipheringAlg = cipherAlg
	ue.UeSecurity.NgKsi.Ksi = 7
	ue.UeSecurity.NgKsi.Tsc = models.ScType_NATIVE

	ue.SetAuthSubscription(opts.K, opts.OpC, opts.Amf, opts.Sqn)

	ue.UeSecurity.mcc = opts.Mcc
	ue.UeSecurity.mnc = opts.Mnc

	ue.UeSecurity.RoutingIndicator = opts.RoutingIndicator
	ue.UeSecurity.suciPublicKey = opts.HomeNetworkPublicKey

	ue.UeSecurity.Supi = fmt.Sprintf("imsi-%s%s%s", opts.Mcc, opts.Mnc, opts.Msin)

	ue.Snssai.Sd = opts.Sd
	ue.Snssai.Sst = opts.Sst

	ue.Dnn = opts.Dnn

	suci, err := ue.EncodeSuci()
	if err != nil {
		return nil, fmt.Errorf("failed to encode SUCI: %v", err)
	}

	ue.UeSecurity.Suci = suci

	ue.StateMM = MM5G_NULL

	return &ue, nil
}

func (ue *UE) SetAuthSubscription(k, opc, amf, sqn string) {
	ue.UeSecurity.AuthenticationSubs.EncPermanentKey = k
	ue.UeSecurity.AuthenticationSubs.EncOpcKey = opc

	ue.UeSecurity.AuthenticationSubs.AuthenticationManagementField = amf

	ue.UeSecurity.AuthenticationSubs.SequenceNumber = &models.SequenceNumber{
		Sqn: sqn,
	}
	ue.UeSecurity.AuthenticationSubs.AuthenticationMethod = models.AuthMethod__5_G_AKA
}

func (ue *UE) EncodeSuci() (nasType.MobileIdentity5GS, error) {
	protScheme, err := strconv.ParseUint(ue.UeSecurity.suciPublicKey.ProtectionScheme, 10, 8)
	if err != nil {
		return nasType.MobileIdentity5GS{}, fmt.Errorf("unable to parse protection scheme: %v", err)
	}

	buf6 := byte(protScheme)

	hnPubKeyId, err := strconv.ParseUint(ue.UeSecurity.suciPublicKey.PublicKeyID, 10, 8)
	if err != nil {
		return nasType.MobileIdentity5GS{}, fmt.Errorf("unable to parse home network public key ID: %v", err)
	}

	buf7 := byte(hnPubKeyId)

	var schemeOutput []byte

	if protScheme == 0 {
		schemeOutput, err = hex.DecodeString(sidf.Tbcd(ue.UeSecurity.Msin))
		if err != nil {
			return nasType.MobileIdentity5GS{}, fmt.Errorf("unable to decode msin to tbcd: %v", err)
		}
	} else {
		suci, err := sidf.CipherSuci(ue.UeSecurity.Msin, ue.UeSecurity.mcc, ue.UeSecurity.mnc, ue.UeSecurity.RoutingIndicator, ue.UeSecurity.suciPublicKey)
		if err != nil {
			return nasType.MobileIdentity5GS{}, fmt.Errorf("unable to cipher SUCI: %v", err)
		}

		schemeOutput, err = hex.DecodeString(suci.SchemeOutput)
		if err != nil {
			return nasType.MobileIdentity5GS{}, fmt.Errorf("unable to decode scheme output to bytes: %v", err)
		}
	}

	buffer := make([]byte, 8+len(schemeOutput))

	buffer[0] = 1

	plmnID, err := ue.GetMccAndMncInOctets()
	if err != nil {
		return nasType.MobileIdentity5GS{}, fmt.Errorf("unable to get mcc and mnc in octets: %v", err)
	}

	copy(buffer[1:], plmnID)

	routingInd, err := ue.GetRoutingIndicatorInOctets()
	if err != nil {
		return nasType.MobileIdentity5GS{}, fmt.Errorf("unable to get routing indicator: %v", err)
	}

	copy(buffer[4:], routingInd)
	buffer[6] = buf6
	buffer[7] = buf7
	copy(buffer[8:], schemeOutput)

	suci := nasType.MobileIdentity5GS{
		Buffer: buffer,
		Len:    uint16(len(buffer)),
	}

	return suci, nil
}

func (ue *UE) GetMccAndMncInOctets() ([]byte, error) {
	var res string

	mcc := reverse(ue.UeSecurity.mcc)
	mnc := reverse(ue.UeSecurity.mnc)

	if len(mnc) == 2 {
		res = fmt.Sprintf("%c%cf%c%c%c", mcc[1], mcc[2], mcc[0], mnc[0], mnc[1])
	} else {
		res = fmt.Sprintf("%c%c%c%c%c%c", mcc[1], mcc[2], mnc[0], mcc[0], mnc[1], mnc[2])
	}

	resu, err := hex.DecodeString(res)
	if err != nil {
		return nil, fmt.Errorf("could not decode string: %v", err)
	}

	return resu, nil
}

// TS 24.501 9.11.3.4.1
// Routing Indicator shall consist of 1 to 4 digits. The coding of this field is the
// responsibility of home network operator but BCD coding shall be used. If a network
// operator decides to assign less than 4 digits to Routing Indicator, the remaining digits
// shall be coded as "1111" to fill the 4 digits coding of Routing Indicator (see NOTE 2). If
// no Routing Indicator is configured in the USIM, the UE shall coxde bits 1 to 4 of octet 8
// of the Routing Indicator as "0000" and the remaining digits as “1111".
func (ue *UE) GetRoutingIndicatorInOctets() ([]byte, error) {
	if len(ue.UeSecurity.RoutingIndicator) == 0 {
		ue.UeSecurity.RoutingIndicator = "0"
	}

	if len(ue.UeSecurity.RoutingIndicator) > 4 {
		return nil, fmt.Errorf("routing indicator must be 4 digits maximum, %s is invalid", ue.UeSecurity.RoutingIndicator)
	}

	routingIndicator := []byte(ue.UeSecurity.RoutingIndicator)
	for len(routingIndicator) < 4 {
		routingIndicator = append(routingIndicator, 'F')
	}

	// Reverse the bytes in group of two
	for i := 1; i < len(routingIndicator); i += 2 {
		tmp := routingIndicator[i-1]
		routingIndicator[i-1] = routingIndicator[i]
		routingIndicator[i] = tmp
	}

	// BCD conversion
	encodedRoutingIndicator, err := hex.DecodeString(string(routingIndicator))
	if err != nil {
		return nil, fmt.Errorf("unable to encode routing indicator %s", err)
	}

	return encodedRoutingIndicator, nil
}

func reverse(s string) string {
	var aux string
	for _, valor := range s {
		aux = string(valor) + aux
	}

	return aux
}
