/**
 * SPDX-License-Identifier: Apache-2.0
 * © Copyright 2023 Hewlett Packard Enterprise Development LP
 * © Copyright 2025 Valentin D'Emmanuele
 */

package context

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/ellanetworks/core-tester/internal/common/auth"
	"github.com/ellanetworks/core-tester/internal/common/sidf"
	"github.com/ellanetworks/core-tester/internal/gnb/context"
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/ellanetworks/core-tester/internal/ue/scenario"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/nas/security"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/milenage"
	"github.com/free5gc/util/ueauth"
	"github.com/vishvananda/netlink"
)

// 5GMM main states in the UE.
const (
	MM5G_NULL                 = 0x00
	MM5G_DEREGISTERED         = 0x01
	MM5G_REGISTERED_INITIATED = 0x02
	MM5G_REGISTERED           = 0x03
	MM5G_SERVICE_REQ_INIT     = 0x04
	MM5G_DEREGISTERED_INIT    = 0x05
	MM5G_IDLE                 = 0x06
)

// 5GSM main states in the UE.
const (
	SM5G_PDU_SESSION_INACTIVE       = 0x00
	SM5G_PDU_SESSION_ACTIVE_PENDING = 0x01
	SM5G_PDU_SESSION_ACTIVE         = 0x02
)

type UEContext struct {
	id                uint8
	prUeId            int64
	UeSecurity        SECURITY
	StateMM           int
	gnbInboundChannel chan context.UEMessage
	gnbRx             chan context.UEMessage
	gnbTx             chan context.UEMessage
	drx               *time.Ticker
	PduSession        [16]*UEPDUSession
	amfInfo           Amf

	Dnn    string
	Snssai models.Snssai

	// Sync primitive
	scenarioChan chan scenario.ScenarioMessage

	lock sync.Mutex
}

type Amf struct {
	mcc string
	mnc string
}

type UEPDUSession struct {
	Id            uint8
	GnbPduSession *context.GnbPDUSession
	ueIP          string
	ueGnbIP       netip.Addr
	tun           netlink.Link
	rule          *netlink.Rule
	routeTun      *netlink.Route
	vrf           *netlink.Vrf
	stopSignal    chan bool
	Wait          chan bool
	T3580Retries  int

	// TS 24.501 - 6.1.3.2.1.1 State Machine for Session Management
	StateSM int
}

type SECURITY struct {
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

func (ue *UEContext) NewRanUeContext(msin string,
	ueSecurityCapability *nasType.UESecurityCapability,
	k, opc, op, amf, sqn, mcc, mnc string, homeNetworkPublicKey sidf.HomeNetworkPublicKey, routingIndicator, dnn string,
	sst int32, sd string, scenarioChan chan scenario.ScenarioMessage,
	gnbInboundChannel chan context.UEMessage, id int,
) error {
	// added SUPI.
	ue.UeSecurity.Msin = msin

	// added ciphering algorithm.
	ue.UeSecurity.UeSecurityCapability = ueSecurityCapability

	integAlg, cipherAlg := auth.SelectAlgorithms(ue.UeSecurity.UeSecurityCapability)

	// set the algorithms of integritys
	ue.UeSecurity.IntegrityAlg = integAlg
	// set the algorithms of ciphering
	ue.UeSecurity.CipheringAlg = cipherAlg

	// No KSI at first start
	ue.UeSecurity.NgKsi.Ksi = 7
	ue.UeSecurity.NgKsi.Tsc = models.ScType_NATIVE

	// added key, AuthenticationManagementField and opc or op.
	ue.SetAuthSubscription(k, opc, op, amf, sqn)

	// added mcc and mnc
	ue.UeSecurity.mcc = mcc
	ue.UeSecurity.mnc = mnc

	// added routing indidcator
	ue.UeSecurity.RoutingIndicator = routingIndicator
	ue.UeSecurity.suciPublicKey = homeNetworkPublicKey

	// added supi
	ue.UeSecurity.Supi = fmt.Sprintf("imsi-%s%s%s", mcc, mnc, msin)

	// added UE id.
	ue.id = uint8(id)
	ue.prUeId = int64(id)

	// added network slice
	ue.Snssai.Sd = sd
	ue.Snssai.Sst = sst

	// added Domain Network Name.
	ue.Dnn = dnn

	suci, err := ue.EncodeSuci()
	if err != nil {
		return fmt.Errorf("failed to encode SUCI: %v", err)
	}
	ue.UeSecurity.Suci = suci

	ue.gnbInboundChannel = gnbInboundChannel
	ue.scenarioChan = scenarioChan

	// added initial state for MM(NULL)
	ue.StateMM = MM5G_NULL
	return nil
}

func (ue *UEContext) CreatePDUSession() (*UEPDUSession, error) {
	pduSessionIndex := -1
	for i, pduSession := range ue.PduSession {
		if pduSession == nil {
			pduSessionIndex = i
			break
		}
	}

	if pduSessionIndex == -1 {
		return nil, errors.New("unable to create an additional PDU Session, we already created the max number of PDU Session")
	}

	pduSession := &UEPDUSession{}
	pduSession.Id = uint8(pduSessionIndex + 1)
	pduSession.Wait = make(chan bool)

	ue.PduSession[pduSessionIndex] = pduSession

	return pduSession, nil
}

func (ue *UEContext) GetUeId() uint8 {
	return ue.id
}

func (ue *UEContext) GetPrUeId() int64 {
	return ue.prUeId
}

func (ue *UEContext) GetSuci() nasType.MobileIdentity5GS {
	return ue.UeSecurity.Suci
}

func (ue *UEContext) GetMsin() string {
	return ue.UeSecurity.Msin
}

func (ue *UEContext) SetStateMM_REGISTERED_INITIATED() {
	ue.StateMM = MM5G_REGISTERED_INITIATED
	ue.scenarioChan <- scenario.ScenarioMessage{StateChange: ue.StateMM}
}

func (ue *UEContext) SetStateMM_REGISTERED() {
	ue.StateMM = MM5G_REGISTERED
	ue.scenarioChan <- scenario.ScenarioMessage{StateChange: ue.StateMM}
}

func (ue *UEContext) SetStateMM_NULL() {
	ue.StateMM = MM5G_NULL
}

func (ue *UEContext) SetStateMM_DEREGISTERED() {
	ue.StateMM = MM5G_DEREGISTERED
	ue.scenarioChan <- scenario.ScenarioMessage{StateChange: ue.StateMM}
}

func (ue *UEContext) SetStateMM_IDLE() {
	ue.StateMM = MM5G_IDLE
	ue.scenarioChan <- scenario.ScenarioMessage{StateChange: ue.StateMM}
}

func (ue *UEContext) GetStateMM() int {
	return ue.StateMM
}

func (ue *UEContext) SetGnbInboundChannel(gnbInboundChannel chan context.UEMessage) {
	ue.gnbInboundChannel = gnbInboundChannel
}

func (ue *UEContext) SetGnbRx(gnbRx chan context.UEMessage) {
	ue.gnbRx = gnbRx
}

func (ue *UEContext) SetGnbTx(gnbTx chan context.UEMessage) {
	ue.gnbTx = gnbTx
}

func (ue *UEContext) GetGnbInboundChannel() chan context.UEMessage {
	return ue.gnbInboundChannel
}

func (ue *UEContext) GetGnbRx() chan context.UEMessage {
	return ue.gnbRx
}

func (ue *UEContext) GetGnbTx() chan context.UEMessage {
	return ue.gnbTx
}

func (ue *UEContext) GetDRX() <-chan time.Time {
	if ue.drx == nil {
		return nil
	}
	return ue.drx.C
}

func (ue *UEContext) StopDRX() {
	if ue.drx != nil {
		ue.drx.Stop()
	}
}

func (ue *UEContext) CreateDRX(d time.Duration) {
	ue.drx = time.NewTicker(d)
}

func (ue *UEContext) Lock() {
	ue.lock.Lock()
}

func (ue *UEContext) Unlock() {
	ue.lock.Unlock()
}

func (ue *UEContext) GetPduSession(pduSessionid uint8) (*UEPDUSession, error) {
	if pduSessionid > 15 || ue.PduSession[pduSessionid-1] == nil {
		return nil, errors.New("Unable to find GnbPDUSession ID " + string(pduSessionid))
	}
	return ue.PduSession[pduSessionid-1], nil
}

func (ue *UEContext) DeletePduSession(pduSessionid uint8) error {
	if pduSessionid > 15 || ue.PduSession[pduSessionid-1] == nil {
		return errors.New("Unable to find GnbPDUSession ID " + string(pduSessionid))
	}
	pduSession := ue.PduSession[pduSessionid-1]
	close(pduSession.Wait)
	stopSignal := pduSession.GetStopSignal()
	if stopSignal != nil {
		stopSignal <- true
	}
	ue.PduSession[pduSessionid-1] = nil
	return nil
}

func (pduSession *UEPDUSession) SetIp(ip [12]uint8) {
	pduSession.ueIP = fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

func (pduSession *UEPDUSession) GetIp() string {
	return pduSession.ueIP
}

func (pduSession *UEPDUSession) SetGnbIp(ip netip.Addr) {
	pduSession.ueGnbIP = ip
}

func (pduSession *UEPDUSession) GetGnbIp() netip.Addr {
	return pduSession.ueGnbIP
}

func (pduSession *UEPDUSession) SetStopSignal(stopSignal chan bool) {
	pduSession.stopSignal = stopSignal
}

func (pduSession *UEPDUSession) GetStopSignal() chan bool {
	return pduSession.stopSignal
}

func (pduSession *UEPDUSession) SetTunInterface(tun netlink.Link) {
	pduSession.tun = tun
}

func (pduSession *UEPDUSession) GetTunInterface() netlink.Link {
	return pduSession.tun
}

func (pduSession *UEPDUSession) SetTunRule(rule *netlink.Rule) {
	pduSession.rule = rule
}

func (pduSession *UEPDUSession) GetTunRule() *netlink.Rule {
	return pduSession.rule
}

func (pduSession *UEPDUSession) SetTunRoute(route *netlink.Route) {
	pduSession.routeTun = route
}

func (pduSession *UEPDUSession) GetTunRoute() *netlink.Route {
	return pduSession.routeTun
}

func (pduSession *UEPDUSession) SetVrfDevice(vrf *netlink.Vrf) {
	pduSession.vrf = vrf
}

func (pduSession *UEPDUSession) GetVrfDevice() *netlink.Vrf {
	return pduSession.vrf
}

func (pdu *UEPDUSession) SetStateSM_PDU_SESSION_INACTIVE() {
	pdu.StateSM = SM5G_PDU_SESSION_INACTIVE
}

func (pdu *UEPDUSession) SetStateSM_PDU_SESSION_ACTIVE() {
	pdu.StateSM = SM5G_PDU_SESSION_ACTIVE
}

func (pdu *UEPDUSession) SetStateSM_PDU_SESSION_PENDING() {
	pdu.StateSM = SM5G_PDU_SESSION_ACTIVE_PENDING
}

func (pduSession *UEPDUSession) GetStateSM() int {
	return pduSession.StateSM
}

func (ue *UEContext) deriveSNN() string {
	// 5G:mnc093.mcc208.3gppnetwork.org
	var resu string
	if len(ue.amfInfo.mnc) == 2 {
		resu = "5G:mnc0" + ue.amfInfo.mnc + ".mcc" + ue.amfInfo.mcc + ".3gppnetwork.org"
	} else {
		resu = "5G:mnc" + ue.amfInfo.mnc + ".mcc" + ue.amfInfo.mcc + ".3gppnetwork.org"
	}
	return resu
}

func (ue *UEContext) GetUeSecurityCapability() *nasType.UESecurityCapability {
	return ue.UeSecurity.UeSecurityCapability
}

func (ue *UEContext) GetMccAndMncInOctets() []byte {
	var res string

	// reverse mcc and mnc
	mcc := reverse(ue.UeSecurity.mcc)
	mnc := reverse(ue.UeSecurity.mnc)

	if len(mnc) == 2 {
		res = fmt.Sprintf("%c%cf%c%c%c", mcc[1], mcc[2], mcc[0], mnc[0], mnc[1])
	} else {
		res = fmt.Sprintf("%c%c%c%c%c%c", mcc[1], mcc[2], mnc[0], mcc[0], mnc[1], mnc[2])
	}

	resu, _ := hex.DecodeString(res)
	return resu
}

// TS 24.501 9.11.3.4.1
// Routing Indicator shall consist of 1 to 4 digits. The coding of this field is the
// responsibility of home network operator but BCD coding shall be used. If a network
// operator decides to assign less than 4 digits to Routing Indicator, the remaining digits
// shall be coded as "1111" to fill the 4 digits coding of Routing Indicator (see NOTE 2). If
// no Routing Indicator is configured in the USIM, the UE shall coxde bits 1 to 4 of octet 8
// of the Routing Indicator as "0000" and the remaining digits as “1111".
func (ue *UEContext) GetRoutingIndicatorInOctets() ([]byte, error) {
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

func (ue *UEContext) EncodeSuci() (nasType.MobileIdentity5GS, error) {
	protScheme, _ := strconv.ParseUint(ue.UeSecurity.suciPublicKey.ProtectionScheme, 10, 8)
	buf6 := byte(protScheme)

	hnPubKeyId, _ := strconv.ParseUint(ue.UeSecurity.suciPublicKey.PublicKeyID, 10, 8)
	buf7 := byte(hnPubKeyId)

	var schemeOutput []byte

	if protScheme == 0 {
		schemeOutput, _ = hex.DecodeString(sidf.Tbcd(ue.UeSecurity.Msin))
	} else {
		suci, err := sidf.CipherSuci(ue.UeSecurity.Msin, ue.UeSecurity.mcc, ue.UeSecurity.mnc, ue.UeSecurity.RoutingIndicator, ue.UeSecurity.suciPublicKey)
		if err != nil {
			return nasType.MobileIdentity5GS{}, fmt.Errorf("unable to cipher SUCI: %v", err)
		}
		schemeOutput, _ = hex.DecodeString(suci.SchemeOutput)
	}

	buffer := make([]byte, 8+len(schemeOutput))

	buffer[0] = 1
	copy(buffer[1:], ue.GetMccAndMncInOctets())
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

func (ue *UEContext) GetAmfPointer() uint8 {
	return ue.UeSecurity.Guti.GetAMFPointer()
}

func (ue *UEContext) GetAmfSetId() uint16 {
	return ue.UeSecurity.Guti.GetAMFSetID()
}

func (ue *UEContext) SetAmfMccAndMnc(mcc string, mnc string) {
	ue.amfInfo.mcc = mcc
	ue.amfInfo.mnc = mnc
	ue.UeSecurity.Snn = ue.deriveSNN()
}

func (ue *UEContext) GetTMSI5G() [4]uint8 {
	if ue.UeSecurity.Guti != nil {
		return ue.UeSecurity.Guti.GetTMSI5G()
	}
	return [4]uint8{}
}

func (ue *UEContext) Set5gGuti(guti *nasType.GUTI5G) {
	ue.UeSecurity.Guti = guti
}

func (ue *UEContext) Get5gGuti() *nasType.GUTI5G {
	return ue.UeSecurity.Guti
}

var (
	ErrMACFailure = errors.New("milenage MAC failure")
	ErrSQNFailure = errors.New("sequence number out of range")
)

func (ue *UEContext) DeriveRESstarAndSetKey(authSubs models.AuthenticationSubscription,
	RAND []byte,
	snNmae string,
	AUTN []byte,
) ([]byte, error) {
	// Get OPC, K, SQN from USIM.
	OPC, err := hex.DecodeString(authSubs.Opc.OpcValue)
	if err != nil {
		return nil, fmt.Errorf("could not decode OPC: %v", err)
	}
	K, err := hex.DecodeString(authSubs.PermanentKey.PermanentKeyValue)
	if err != nil {
		return nil, fmt.Errorf("could not decode K: %v", err)
	}
	sqnUe, err := hex.DecodeString(authSubs.SequenceNumber)
	if err != nil {
		return nil, fmt.Errorf("could not decode SQN: %v", err)
	}

	sqnHn, AK, IK, CK, RES, err := milenage.GenerateKeysWithAUTN(OPC, K, RAND, AUTN)
	if err != nil {
		return nil, ErrMACFailure
	}

	// Verification of sequence number freshness.
	if bytes.Compare(sqnUe, sqnHn) > 0 {
		auts, err := milenage.GenerateAUTS(OPC, K, RAND, sqnUe)
		if err != nil {
			return auts, fmt.Errorf("AUTS generation error: %v", err)
		}

		return auts, ErrSQNFailure
	}

	// updated sqn value.
	authSubs.SequenceNumber = fmt.Sprintf("%08x", sqnHn)

	// derive RES*
	key := append(CK, IK...)
	FC := ueauth.FC_FOR_RES_STAR_XRES_STAR_DERIVATION
	P0 := []byte(snNmae)
	P1 := RAND
	P2 := RES

	err = ue.DerivateKamf(key, snNmae, sqnHn, AK)
	if err != nil {
		return nil, fmt.Errorf("error while deriving Kamf: %v", err)
	}
	kdfVal_for_resStar, err := ueauth.GetKDFValue(key, FC, P0, ueauth.KDFLen(P0), P1, ueauth.KDFLen(P1), P2, ueauth.KDFLen(P2))
	if err != nil {
		return nil, fmt.Errorf("error while deriving KDF: %v", err)
	}
	return kdfVal_for_resStar[len(kdfVal_for_resStar)/2:], nil
}

func (ue *UEContext) DerivateKamf(key []byte, snName string, SQN, AK []byte) error {
	FC := ueauth.FC_FOR_KAUSF_DERIVATION
	P0 := []byte(snName)
	SQNxorAK := make([]byte, 6)
	for i := 0; i < len(SQN); i++ {
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

func (ue *UEContext) DerivateAlgKey() error {
	err := auth.AlgorithmKeyDerivation(ue.UeSecurity.CipheringAlg,
		ue.UeSecurity.Kamf,
		&ue.UeSecurity.KnasEnc,
		ue.UeSecurity.IntegrityAlg,
		&ue.UeSecurity.KnasInt)
	if err != nil {
		return fmt.Errorf("algorithm key derivation failed: %v", err)
	}
	return nil
}

func (ue *UEContext) SetAuthSubscription(k, opc, op, amf, sqn string) {
	ue.UeSecurity.AuthenticationSubs.PermanentKey = &models.PermanentKey{
		PermanentKeyValue: k,
	}
	ue.UeSecurity.AuthenticationSubs.Opc = &models.Opc{
		OpcValue: opc,
	}
	ue.UeSecurity.AuthenticationSubs.Milenage = &models.Milenage{
		Op: &models.Op{
			OpValue: op,
		},
	}
	ue.UeSecurity.AuthenticationSubs.AuthenticationManagementField = amf

	ue.UeSecurity.AuthenticationSubs.SequenceNumber = sqn
	ue.UeSecurity.AuthenticationSubs.AuthenticationMethod = models.AuthMethod__5_G_AKA
}

func (ue *UEContext) Terminate() {
	ue.SetStateMM_NULL()

	// clean all context of tun interface
	for _, pduSession := range ue.PduSession {
		if pduSession != nil {
			ueTun := pduSession.GetTunInterface()
			ueRule := pduSession.GetTunRule()
			ueRoute := pduSession.GetTunRoute()
			ueVrf := pduSession.GetVrfDevice()

			if ueTun != nil {
				_ = netlink.LinkSetDown(ueTun)
				_ = netlink.LinkDel(ueTun)
			}

			if ueRule != nil {
				_ = netlink.RuleDel(ueRule)
			}

			if ueRoute != nil {
				_ = netlink.RouteDel(ueRoute)
			}

			if ueVrf != nil {
				_ = netlink.LinkSetDown(ueVrf)
				_ = netlink.LinkDel(ueVrf)
			}
		}
	}

	ue.Lock()
	if ue.gnbRx != nil {
		close(ue.gnbRx)
		ue.gnbRx = nil
	}
	if ue.drx != nil {
		ue.drx.Stop()
	}
	ue.Unlock()
	close(ue.scenarioChan)

	logger.UELog.Info("ue terminated")
}

func reverse(s string) string {
	// reverse string.
	var aux string
	for _, valor := range s {
		aux = string(valor) + aux
	}
	return aux
}
