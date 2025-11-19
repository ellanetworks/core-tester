package ue

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/ellanetworks/core-tester/internal/air"
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/ellanetworks/core-tester/internal/tests/tests/utils"
	"github.com/ellanetworks/core-tester/internal/ue/sidf"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/nas/security"
	"github.com/free5gc/ngap/ngapType"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/milenage"
	"github.com/free5gc/util/ueauth"
	"go.uber.org/zap"
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

type Amf struct {
	mcc string
	mnc string
}

type UE struct {
	UeSecurity   *UESecurity
	StateMM      int
	DNN          string
	PDUSessionID uint8
	Snssai       models.Snssai
	amfInfo      Amf
	IMEISV       string
	Gnb          air.UplinkSender
	mu           sync.Mutex
	PDUSession   PDUSessionInfo
}

func (ue *UE) SetPDUSession(pduSession PDUSessionInfo) {
	ue.mu.Lock()
	defer ue.mu.Unlock()
	ue.PDUSession = pduSession
}

func (ue *UE) GetPDUSession() PDUSessionInfo {
	ue.mu.Lock()
	defer ue.mu.Unlock()

	return ue.PDUSession
}

func (ue *UE) WaitForPDUSession(timeout time.Duration) (PDUSessionInfo, error) {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		ue.mu.Lock()
		pduSession := ue.PDUSession
		ue.mu.Unlock()

		if pduSession.PDUSessionID != 0 {
			return pduSession, nil
		}

		time.Sleep(10 * time.Millisecond)
	}

	return PDUSessionInfo{}, errors.New("timeout waiting for PDU session")
}

type UEOpts struct {
	PDUSessionID         uint8
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
	DNN                  string
	Sst                  int32
	Sd                   string
	IMEISV               string
	Guti                 *nasType.GUTI5G
	GnodeB               air.UplinkSender
}

func NewUE(opts *UEOpts) (*UE, error) {
	ue := UE{}
	ue.UeSecurity = &UESecurity{}
	ue.UeSecurity.Msin = opts.Msin
	ue.UeSecurity.UeSecurityCapability = opts.UeSecurityCapability
	ue.Gnb = opts.GnodeB
	ue.PDUSessionID = opts.PDUSessionID

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

	ue.DNN = opts.DNN

	ue.IMEISV = opts.IMEISV

	suci, err := ue.EncodeSuci()
	if err != nil {
		return nil, fmt.Errorf("failed to encode SUCI: %v", err)
	}

	ue.SetAmfMccAndMnc(opts.Mcc, opts.Mnc)

	ue.UeSecurity.Suci = suci

	if opts.Guti != nil {
		ue.Set5gGuti(opts.Guti)
	}

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

var (
	ErrMACFailure = errors.New("milenage MAC failure")
	ErrSQNFailure = errors.New("sequence number out of range")
)

func (ue *UE) DeriveRESstarAndSetKey(authSubs models.AuthenticationSubscription, RAND []byte, snName string, AUTN []byte) ([]byte, error) {
	OPC, err := hex.DecodeString(authSubs.EncOpcKey)
	if err != nil {
		return nil, fmt.Errorf("could not decode OPC: %v", err)
	}

	K, err := hex.DecodeString(authSubs.EncPermanentKey)
	if err != nil {
		return nil, fmt.Errorf("could not decode K: %v", err)
	}

	sqnUe, err := hex.DecodeString(authSubs.SequenceNumber.Sqn)
	if err != nil {
		return nil, fmt.Errorf("could not decode SQN: %v", err)
	}

	sqnHn, AK, IK, CK, RES, err := milenage.GenerateKeysWithAUTN(OPC, K, RAND, AUTN)
	if err != nil {
		return nil, ErrMACFailure
	}

	if bytes.Compare(sqnUe, sqnHn) > 0 {
		auts, err := milenage.GenerateAUTS(OPC, K, RAND, sqnUe)
		if err != nil {
			return auts, fmt.Errorf("AUTS generation error: %v", err)
		}

		return auts, ErrSQNFailure
	}

	authSubs.SequenceNumber = &models.SequenceNumber{
		Sqn: fmt.Sprintf("%08x", sqnHn),
	}

	key := append(CK, IK...)
	FC := ueauth.FC_FOR_RES_STAR_XRES_STAR_DERIVATION
	P0 := []byte(snName)
	P1 := RAND
	P2 := RES

	err = ue.DerivateKamf(key, snName, sqnHn, AK)
	if err != nil {
		return nil, fmt.Errorf("error while deriving Kamf: %v", err)
	}

	kdfVal_for_resStar, err := ueauth.GetKDFValue(key, FC, P0, ueauth.KDFLen(P0), P1, ueauth.KDFLen(P1), P2, ueauth.KDFLen(P2))
	if err != nil {
		return nil, fmt.Errorf("error while deriving KDF: %v", err)
	}

	return kdfVal_for_resStar[len(kdfVal_for_resStar)/2:], nil
}

func (ue *UE) DerivateKamf(key []byte, snName string, SQN, AK []byte) error {
	FC := ueauth.FC_FOR_KAUSF_DERIVATION
	P0 := []byte(snName)
	SQNxorAK := make([]byte, 6)

	for i := range SQN {
		SQNxorAK[i] = SQN[i] ^ AK[i]
	}

	P1 := SQNxorAK

	Kausf, err := ueauth.GetKDFValue(key, FC, P0, ueauth.KDFLen(P0), P1, ueauth.KDFLen(P1))
	if err != nil {
		return fmt.Errorf("error while deriving Kausf: %v", err)
	}

	P0 = []byte(snName)

	Kseaf, err := ueauth.GetKDFValue(Kausf, ueauth.FC_FOR_KSEAF_DERIVATION, P0, ueauth.KDFLen(P0))
	if err != nil {
		return fmt.Errorf("error while deriving Kseaf: %v", err)
	}

	supiRegexp, _ := regexp.Compile("(?:imsi|supi)-([0-9]{5,15})")
	groups := supiRegexp.FindStringSubmatch(ue.UeSecurity.Supi)

	P0 = []byte(groups[1])
	L0 := ueauth.KDFLen(P0)
	P1 = []byte{0x00, 0x00}
	L1 := ueauth.KDFLen(P1)

	ue.UeSecurity.Kamf, err = ueauth.GetKDFValue(Kseaf, ueauth.FC_FOR_KAMF_DERIVATION, P0, L0, P1, L1)
	if err != nil {
		return fmt.Errorf("error while deriving Kamf: %v", err)
	}

	return nil
}

func (ue *UE) SetAmfMccAndMnc(mcc string, mnc string) {
	ue.amfInfo.mcc = mcc
	ue.amfInfo.mnc = mnc
	ue.UeSecurity.Snn = ue.deriveSNN()
}

// Build SNN (// 5G:mnc093.mcc208.3gppnetwork.org)
func (ue *UE) deriveSNN() string {
	var resu string
	if len(ue.amfInfo.mnc) == 2 {
		resu = "5G:mnc0" + ue.amfInfo.mnc + ".mcc" + ue.amfInfo.mcc + ".3gppnetwork.org"
	} else {
		resu = "5G:mnc" + ue.amfInfo.mnc + ".mcc" + ue.amfInfo.mcc + ".3gppnetwork.org"
	}

	return resu
}

func (ue *UE) Set5gGuti(guti *nasType.GUTI5G) {
	ue.UeSecurity.Guti = guti
}

func (ue *UE) Get5gGuti() *nasType.GUTI5G {
	return ue.UeSecurity.Guti
}

func (ue *UE) GetAmfSetId() uint16 {
	return ue.UeSecurity.Guti.GetAMFSetID()
}

func (ue *UE) GetAmfPointer() uint8 {
	return ue.UeSecurity.Guti.GetAMFPointer()
}

func (ue *UE) GetTMSI5G() [4]uint8 {
	if ue.UeSecurity.Guti != nil {
		return ue.UeSecurity.Guti.GetTMSI5G()
	}

	return [4]uint8{}
}

func (ue *UE) GetSuci() nasType.MobileIdentity5GS {
	return ue.UeSecurity.Suci
}

func (ue *UE) SendDownlinkNAS(msg []byte, amfUENGAPID int64, ranUENGAPID int64) error {
	decodedMsg, err := ue.DecodeNAS(msg)
	if err != nil {
		return fmt.Errorf("could not decode NAS message: %v", err)
	}

	msgType := decodedMsg.GmmMessage.GetMessageType()

	switch msgType {
	case nas.MsgTypeAuthenticationReject:
		return handleAuthenticationReject(ue, decodedMsg)
	case nas.MsgTypeAuthenticationRequest:
		return handleAuthenticationRequest(ue, decodedMsg, amfUENGAPID, ranUENGAPID)
	case nas.MsgTypeSecurityModeCommand:
		return handleSecurityModeCommand(ue, decodedMsg, amfUENGAPID, ranUENGAPID)
	case nas.MsgTypeRegistrationAccept:
		return handleRegistrationAccept(ue, decodedMsg, amfUENGAPID, ranUENGAPID)
	case nas.MsgTypeRegistrationReject:
		return handleRegistrationReject(ue, decodedMsg)
	case nas.MsgTypeDeregistrationRequestUETerminatedDeregistration:
		return handleDeregistrationRequestUETerminated(ue, decodedMsg, amfUENGAPID, ranUENGAPID)
	case nas.MsgTypeIdentityRequest:
		return handleIdentityRequest(ue, amfUENGAPID, ranUENGAPID)
	case nas.MsgTypeServiceAccept:
		return handleServiceAccept(ue, decodedMsg)
	case nas.MsgTypeDLNASTransport:
		return handleDLNASTransport(ue, decodedMsg)
	default:
		return fmt.Errorf("NAS message type %d handling not implemented", msgType)
	}
}

func handleAuthenticationReject(ue *UE, _ *nas.Message) error {
	logger.UeLogger.Debug("Received Authentication Reject NAS message", zap.String("IMSI", ue.UeSecurity.Supi))
	return nil
}

func handleRegistrationAccept(ue *UE, msg *nas.Message, amfUENGAPID int64, ranUENGAPID int64) error {
	logger.UeLogger.Debug("Received Registration Accept NAS message", zap.String("IMSI", ue.UeSecurity.Supi))

	ue.Set5gGuti(msg.RegistrationAccept.GUTI5G)

	regComplete, err := BuildRegistrationComplete(&RegistrationCompleteOpts{
		SORTransparentContainer: nil,
	})
	if err != nil {
		return fmt.Errorf("could not build Registration Complete NAS PDU: %v", err)
	}

	encodedPdu, err := ue.EncodeNasPduWithSecurity(regComplete, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered)
	if err != nil {
		return fmt.Errorf("error encoding %s IMSI UE NAS Registration Complete Msg", ue.UeSecurity.Supi)
	}

	err = ue.Gnb.SendUplinkNAS(encodedPdu, amfUENGAPID, ranUENGAPID)
	if err != nil {
		return fmt.Errorf("could not send UplinkNASTransport: %v", err)
	}

	logger.UeLogger.Debug(
		"Sent Registration Complete NAS message",
		zap.String("IMSI", ue.UeSecurity.Supi),
	)

	pduReq, err := BuildPduSessionEstablishmentRequest(&PduSessionEstablishmentRequestOpts{
		PDUSessionID: ue.PDUSessionID,
	})
	if err != nil {
		return fmt.Errorf("could not build PDU Session Establishment Request: %v", err)
	}

	pduUplink, err := BuildUplinkNasTransport(&UplinkNasTransportOpts{
		PDUSessionID:     ue.PDUSessionID,
		PayloadContainer: pduReq,
		DNN:              ue.DNN,
		SNSSAI:           ue.Snssai,
	})
	if err != nil {
		return fmt.Errorf("could not build Uplink NAS Transport for PDU Session: %v", err)
	}

	encodedPdu, err = ue.EncodeNasPduWithSecurity(pduUplink, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered)
	if err != nil {
		return fmt.Errorf("error encoding %s IMSI UE NAS Uplink NAS Transport for PDU Session Msg", ue.UeSecurity.Supi)
	}

	err = ue.Gnb.SendUplinkNAS(encodedPdu, amfUENGAPID, ranUENGAPID)
	if err != nil {
		return fmt.Errorf("could not send UplinkNASTransport for PDU Session Establishment: %v", err)
	}

	logger.UeLogger.Debug(
		"Sent PDU Session Establishment Request",
		zap.String("IMSI", ue.UeSecurity.Supi),
	)

	return nil
}

func handleRegistrationReject(ue *UE, _ *nas.Message) error {
	logger.UeLogger.Debug("Received Registration Reject NAS message", zap.String("IMSI", ue.UeSecurity.Supi))
	return nil
}

func handleDeregistrationRequestUETerminated(ue *UE, _ *nas.Message, amfUENGAPID int64, ranUENGAPID int64) error {
	logger.UeLogger.Debug("Received Deregistration Request UE Terminated NAS message")
	return nil
}

func handleAuthenticationRequest(ue *UE, msg *nas.Message, amfUENGAPID int64, ranUENGAPID int64) error {
	logger.UeLogger.Debug("Received Authentication Request NAS message")

	rand := msg.GetRANDValue()
	autn := msg.GetAUTN()

	paramAutn, err := ue.DeriveRESstarAndSetKey(ue.UeSecurity.AuthenticationSubs, rand[:], ue.UeSecurity.Snn, autn[:])
	if err != nil {
		return fmt.Errorf("could not derive RES* and set key: %v", err)
	}

	authResp, err := BuildAuthenticationResponse(&AuthenticationResponseOpts{
		AuthenticationResponseParam: paramAutn,
		EapMsg:                      "",
	})
	if err != nil {
		return fmt.Errorf("could not build authentication response: %v", err)
	}

	err = ue.Gnb.SendUplinkNAS(authResp, amfUENGAPID, ranUENGAPID)
	if err != nil {
		return fmt.Errorf("could not send Authentication Response: %v", err)
	}

	logger.UeLogger.Debug(
		"Sent Authentication Response NAS message",
		zap.String("IMSI", ue.UeSecurity.Supi),
	)

	return nil
}

func handleSecurityModeCommand(ue *UE, msg *nas.Message, amfUENGAPID int64, ranUENGAPID int64) error {
	if ue.Gnb == nil {
		return fmt.Errorf("GNB is not set for UE")
	}

	logger.UeLogger.Debug("Received Security Mode Command NAS message")

	ksi := int32(msg.SecurityModeCommand.GetNasKeySetIdentifiler())

	var tsc models.ScType

	switch msg.SecurityModeCommand.GetTSC() {
	case nasMessage.TypeOfSecurityContextFlagNative:
		tsc = models.ScType_NATIVE
	case nasMessage.TypeOfSecurityContextFlagMapped:
		tsc = models.ScType_MAPPED
	}

	ue.UeSecurity.NgKsi.Ksi = ksi
	ue.UeSecurity.NgKsi.Tsc = tsc

	logger.UeLogger.Debug(
		"Updated UE security NG KSI",
		zap.Int32("KSI", ksi),
		zap.String("TSC", string(tsc)),
	)

	securityModeComplete, err := BuildSecurityModeComplete(&SecurityModeCompleteOpts{
		UESecurity: ue.UeSecurity,
		IMEISV:     ue.IMEISV,
	})
	if err != nil {
		return fmt.Errorf("error sending Security Mode Complete: %w", err)
	}

	encodedPdu, err := ue.EncodeNasPduWithSecurity(securityModeComplete, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext)
	if err != nil {
		return fmt.Errorf("error encoding %s IMSI UE  NAS Security Mode Complete message: %v", ue.UeSecurity.Supi, err)
	}

	err = ue.Gnb.SendUplinkNAS(encodedPdu, amfUENGAPID, ranUENGAPID)
	if err != nil {
		return fmt.Errorf("could not send UplinkNASTransport: %v", err)
	}

	logger.UeLogger.Debug(
		"Sent Security Mode Complete NAS message",
		zap.String("IMSI", ue.UeSecurity.Supi),
	)

	return nil
}

func handleIdentityRequest(ue *UE, amfUENGAPID int64, ranUENGAPID int64) error {
	logger.UeLogger.Debug("Received Identity Request NAS message")

	identityResp, err := BuildIdentityResponse(&IdentityResponseOpts{
		Suci: ue.GetSuci(),
	})
	if err != nil {
		return fmt.Errorf("could not build Identity Response NAS PDU: %v", err)
	}

	err = ue.Gnb.SendUplinkNAS(identityResp, amfUENGAPID, ranUENGAPID)
	if err != nil {
		return fmt.Errorf("could not send UplinkNASTransport: %v", err)
	}

	logger.UeLogger.Debug(
		"Sent Identity Response NAS message",
		zap.String("IMSI", ue.UeSecurity.Supi),
	)

	return nil
}

func handleServiceAccept(ue *UE, _ *nas.Message) error {
	logger.UeLogger.Debug("Received Service Accept NAS message", zap.String("IMSI", ue.UeSecurity.Supi))
	return nil
}

func handleDLNASTransport(ue *UE, msg *nas.Message) error {
	pduSessionID := msg.DLNASTransport.GetPduSessionID2Value()

	payloadContainer, err := utils.GetNasPduFromPduAccept(msg)
	if err != nil {
		return fmt.Errorf("could not get PDU Session establishment accept: %v", err)
	}

	logger.UeLogger.Debug(
		"Received DL NAS Transport NAS message",
		zap.String("IMSI", ue.UeSecurity.Supi),
		zap.Uint8("PDU Session ID", pduSessionID),
	)

	pcMsgType := payloadContainer.GsmHeader.GetMessageType()

	switch pcMsgType {
	case nas.MsgTypePDUSessionEstablishmentAccept:
		return handlePDUSessionEstablishmentAccept(ue, payloadContainer.PDUSessionEstablishmentAccept)
	case nas.MsgTypePDUSessionEstablishmentReject:
		return handlePDUSessionEstablishmentReject(ue, payloadContainer.PDUSessionEstablishmentReject)
	default:
		return fmt.Errorf("message type not implemented: %v", getMessageName(pcMsgType))
	}
}

func getMessageName(msgType uint8) string {
	switch msgType {
	case nas.MsgTypePDUSessionEstablishmentRequest:
		return "PDU Session Establishment Request"
	case nas.MsgTypePDUSessionEstablishmentAccept:
		return "PDU Session Establishment Accept"
	case nas.MsgTypePDUSessionEstablishmentReject:
		return "PDU Session Establishment Reject"
	case nas.MsgTypePDUSessionAuthenticationCommand:
		return "PDU Session Authentication Command"
	case nas.MsgTypePDUSessionAuthenticationComplete:
		return "PDU Session Authentication Complete"
	case nas.MsgTypePDUSessionAuthenticationResult:
		return "PDU Session Authentication Result"
	case nas.MsgTypePDUSessionModificationRequest:
		return "PDU Session Modification Request"
	case nas.MsgTypePDUSessionModificationReject:
		return "PDU Session Modification Reject"
	case nas.MsgTypePDUSessionModificationCommand:
		return "PDU Session Modification Command"
	case nas.MsgTypePDUSessionModificationComplete:
		return "PDU Session Modification Complete"
	case nas.MsgTypePDUSessionModificationCommandReject:
		return "PDU Session Modification Command Reject"
	case nas.MsgTypePDUSessionReleaseRequest:
		return "PDU Session Release Request"
	case nas.MsgTypePDUSessionReleaseReject:
		return "PDU Session Release Reject"
	case nas.MsgTypePDUSessionReleaseCommand:
		return "PDU Session Release Command"
	case nas.MsgTypePDUSessionReleaseComplete:
		return "PDU Session Release Complete"
	case nas.MsgTypeStatus5GSM:
		return "5GSM Status"
	default:
		return "Unknown Message Type"
	}
}

type PDUSessionInfo struct {
	PDUSessionID uint8
	UEIP         string
}

func handlePDUSessionEstablishmentAccept(ue *UE, msg *nasMessage.PDUSessionEstablishmentAccept) error {
	ueIP, err := utils.UEIPFromNAS(msg.GetPDUAddressInformation())
	if err != nil {
		return fmt.Errorf("could not get UE IP from NAS PDU Address Information: %v", err)
	}

	logger.UeLogger.Debug(
		"Received PDU Session Establishment Accept NAS message",
		zap.String("IMSI", ue.UeSecurity.Supi),
		zap.Uint8("PDU Session ID", msg.GetPDUSessionID()),
		zap.String("UE IP", ueIP.String()),
	)

	ue.SetPDUSession(PDUSessionInfo{
		PDUSessionID: msg.GetPDUSessionID(),
		UEIP:         ueIP.String(),
	})

	return nil
}

func handlePDUSessionEstablishmentReject(ue *UE, msg *nasMessage.PDUSessionEstablishmentReject) error {
	cause := msg.GetCauseValue()

	logger.UeLogger.Debug(
		"Received PDU Session Establishment Reject NAS message",
		zap.String("IMSI", ue.UeSecurity.Supi),
		zap.Uint8("PDU Session ID", msg.GetPDUSessionID()),
		zap.String("Cause", cause5GSMToString(cause)),
	)

	return nil
}

func (ue *UE) SendRegistrationRequest(ranUENGAPID int64, regType uint8) error {
	if ue.Gnb == nil {
		return fmt.Errorf("GNB is not set for UE")
	}

	nasPDU, err := BuildRegistrationRequest(&RegistrationRequestOpts{
		RegistrationType:  regType,
		RequestedNSSAI:    nil,
		UplinkDataStatus:  nil,
		IncludeCapability: false,
		UESecurity:        ue.UeSecurity,
	})
	if err != nil {
		return fmt.Errorf("could not build Registration Request NAS PDU: %v", err)
	}

	err = ue.Gnb.SendInitialUEMessage(nasPDU, ranUENGAPID, ue.UeSecurity.Guti, ngapType.RRCEstablishmentCausePresentMoSignalling)
	if err != nil {
		return fmt.Errorf("could not send UplinkNASTransport: %v", err)
	}

	logger.UeLogger.Debug(
		"Sent Security Mode Complete NAS message",
		zap.String("IMSI", ue.UeSecurity.Supi),
	)

	return nil
}

func (ue *UE) SendServiceRequest(ranUENGAPID int64, pduSessionStatus [16]bool) error {
	serviceRequest, err := BuildServiceRequest(&ServiceRequestOpts{
		ServiceType:      nasMessage.ServiceTypeData,
		AMFSetID:         ue.GetAmfSetId(),
		AMFPointer:       ue.GetAmfPointer(),
		TMSI5G:           ue.GetTMSI5G(),
		PDUSessionStatus: &pduSessionStatus,
		UESecurity:       ue.UeSecurity,
	})
	if err != nil {
		return fmt.Errorf("could not build Service Request NAS PDU: %v", err)
	}

	encodedPdu, err := ue.EncodeNasPduWithSecurity(serviceRequest, nas.SecurityHeaderTypeIntegrityProtected)
	if err != nil {
		return fmt.Errorf("error encoding %s IMSI UE  NAS Security Mode Complete message: %v", ue.UeSecurity.Supi, err)
	}

	err = ue.Gnb.SendInitialUEMessage(encodedPdu, ranUENGAPID, ue.UeSecurity.Guti, ngapType.RRCEstablishmentCausePresentMoData)
	if err != nil {
		return fmt.Errorf("could not send UplinkNASTransport: %v", err)
	}

	logger.UeLogger.Debug(
		"Sent Service Request NAS message",
		zap.String("IMSI", ue.UeSecurity.Supi),
		zap.Int64("RAN UE NGAP ID", ranUENGAPID),
	)

	return nil
}

func (ue *UE) SendDeregistrationRequest(amfUENGAPID int64, ranUENGAPID int64) error {
	deregBytes, err := BuildDeregistrationRequest(&DeregistrationRequestOpts{
		Guti: ue.UeSecurity.Guti,
		Ksi:  ue.UeSecurity.NgKsi.Ksi,
	})
	if err != nil {
		return fmt.Errorf("could not build Deregistration Request NAS PDU: %v", err)
	}

	encodedPdu, err := ue.EncodeNasPduWithSecurity(deregBytes, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered)
	if err != nil {
		return fmt.Errorf("error encoding %s IMSI UE NAS Deregistration Msg", ue.UeSecurity.Supi)
	}

	err = ue.Gnb.SendUplinkNAS(encodedPdu, amfUENGAPID, ranUENGAPID)
	if err != nil {
		return fmt.Errorf("could not send UplinkNASTransport: %v", err)
	}

	logger.UeLogger.Debug(
		"Sent Deregistration Request NAS message",
		zap.String("IMSI", ue.UeSecurity.Supi),
	)

	return nil
}

func (ue *UE) SendPDUSessionEstablishmentRequest(amfUENGAPID int64, ranUENGAPID int64) error {
	pduReq, err := BuildPduSessionEstablishmentRequest(&PduSessionEstablishmentRequestOpts{
		PDUSessionID: ue.PDUSessionID,
	})
	if err != nil {
		return fmt.Errorf("could not build PDU Session Establishment Request: %v", err)
	}

	pduUplink, err := BuildUplinkNasTransport(&UplinkNasTransportOpts{
		PDUSessionID:     ue.PDUSessionID,
		PayloadContainer: pduReq,
		DNN:              ue.DNN,
		SNSSAI:           ue.Snssai,
	})
	if err != nil {
		return fmt.Errorf("could not build Uplink NAS Transport for PDU Session: %v", err)
	}

	encodedPdu, err := ue.EncodeNasPduWithSecurity(pduUplink, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered)
	if err != nil {
		return fmt.Errorf("error encoding %s IMSI UE NAS Uplink NAS Transport for PDU Session Msg", ue.UeSecurity.Supi)
	}

	err = ue.Gnb.SendUplinkNAS(encodedPdu, amfUENGAPID, ranUENGAPID)
	if err != nil {
		return fmt.Errorf("could not send UplinkNASTransport for PDU Session Establishment: %v", err)
	}

	logger.UeLogger.Debug(
		"Sent PDU Session Establishment Request",
		zap.String("IMSI", ue.UeSecurity.Supi),
	)

	return nil
}
