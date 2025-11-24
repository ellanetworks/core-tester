package ue

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/ellanetworks/core-tester/internal/gnb"
	"github.com/ellanetworks/core-tester/internal/logger"
	"github.com/ellanetworks/core-tester/internal/tests/engine"
	"github.com/ellanetworks/core-tester/internal/tests/tests/utils"
	"github.com/ellanetworks/core-tester/internal/tests/tests/utils/core"
	"github.com/ellanetworks/core-tester/internal/ue"
	"github.com/ellanetworks/core-tester/internal/ue/sidf"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/ngap/ngapType"
)

type AuthenticationWrongKey struct{}

func (AuthenticationWrongKey) Meta() engine.Meta {
	return engine.Meta{
		ID:      "ue/authentication/wrong_key",
		Summary: "UE authentication failure test validating the Authentication Request and Response procedures",
		Timeout: 5 * time.Second,
	}
}

func (t AuthenticationWrongKey) Run(ctx context.Context, env engine.Env) error {
	ellaCoreEnv := core.NewEllaCoreEnv(env.EllaCoreClient, core.EllaCoreConfig{
		Operator: core.OperatorConfig{
			ID: core.OperatorID{
				MCC: env.Config.EllaCore.MCC,
				MNC: env.Config.EllaCore.MNC,
			},
			Slice: core.OperatorSlice{
				SST: env.Config.EllaCore.SST,
				SD:  env.Config.EllaCore.SD,
			},
			Tracking: core.OperatorTracking{
				SupportedTACs: []string{env.Config.EllaCore.TAC},
			},
		},
		DataNetworks: []core.DataNetworkConfig{
			{
				Name:   env.Config.EllaCore.DNN,
				IPPool: "10.45.0.0/16",
				DNS:    "8.8.8.8",
				Mtu:    1500,
			},
		},
		Policies: []core.PolicyConfig{
			{
				Name:            env.Config.Subscriber.PolicyName,
				BitrateUplink:   "100 Mbps",
				BitrateDownlink: "100 Mbps",
				Var5qi:          9,
				Arp:             15,
				DataNetworkName: env.Config.EllaCore.DNN,
			},
		},
		Subscribers: []core.SubscriberConfig{
			{
				Imsi:           env.Config.Subscriber.IMSI,
				Key:            env.Config.Subscriber.Key,
				SequenceNumber: env.Config.Subscriber.SequenceNumber,
				OPc:            env.Config.Subscriber.OPC,
				PolicyName:     env.Config.Subscriber.PolicyName,
			},
		},
	})

	err := ellaCoreEnv.Create(ctx)
	if err != nil {
		return fmt.Errorf("could not create EllaCore environment: %v", err)
	}

	logger.Logger.Debug("Created EllaCore environment")

	gNodeB, err := gnb.Start(
		GNBID,
		env.Config.EllaCore.MCC,
		env.Config.EllaCore.MNC,
		env.Config.EllaCore.SST,
		env.Config.EllaCore.SD,
		env.Config.EllaCore.DNN,
		env.Config.EllaCore.TAC,
		"Ella-Core-Tester",
		env.Config.EllaCore.N2Address,
		env.Config.Gnb.N2Address,
		"0.0.0.0",
	)
	if err != nil {
		return fmt.Errorf("error starting gNB: %v", err)
	}

	defer gNodeB.Close()

	_, err = gNodeB.WaitForMessage(ngapType.NGAPPDUPresentSuccessfulOutcome, ngapType.SuccessfulOutcomePresentNGSetupResponse, 200*time.Millisecond)
	if err != nil {
		return fmt.Errorf("timeout waiting for NGSetupComplete: %v", err)
	}

	newUE, err := ue.NewUE(&ue.UEOpts{
		GnodeB: gNodeB,
		Msin:   env.Config.Subscriber.IMSI[5:],
		K:      env.Config.Subscriber.Key,
		OpC:    env.Config.Subscriber.OPC,
		Amf:    "80000000000000000000000000000000",
		Sqn:    env.Config.Subscriber.SequenceNumber,
		Mcc:    env.Config.EllaCore.MCC,
		Mnc:    env.Config.EllaCore.MNC,
		HomeNetworkPublicKey: sidf.HomeNetworkPublicKey{
			ProtectionScheme: sidf.NullScheme,
			PublicKeyID:      "0",
		},
		RoutingIndicator: "0000",
		DNN:              env.Config.EllaCore.DNN,
		Sst:              env.Config.EllaCore.SST,
		Sd:               env.Config.EllaCore.SD,
		IMEISV:           "3569380356438091",
		UeSecurityCapability: utils.GetUESecurityCapability(&utils.UeSecurityCapability{
			Integrity: utils.IntegrityAlgorithms{
				Nia2: true,
			},
			Ciphering: utils.CipheringAlgorithms{
				Nea0: true,
				Nea2: true,
			},
		}),
	})
	if err != nil {
		return fmt.Errorf("could not create UE: %v", err)
	}

	gNodeB.AddUE(RANUENGAPID, newUE)

	err = sendAuthenticationResponseWithWrongKey(RANUENGAPID, newUE)
	if err != nil {
		return fmt.Errorf("initial registration procedure failed: %v", err)
	}

	// Cleanup
	err = ellaCoreEnv.Delete(ctx)
	if err != nil {
		return fmt.Errorf("could not delete EllaCore environment: %v", err)
	}

	logger.Logger.Debug("Deleted EllaCore environment")

	return nil
}

func sendAuthenticationResponseWithWrongKey(ranUENGAPID int64, ue *ue.UE) error {
	err := ue.SendRegistrationRequest(ranUENGAPID, nasMessage.RegistrationType5GSInitialRegistration)
	if err != nil {
		return fmt.Errorf("could not build Registration Request NAS PDU: %v", err)
	}

	// The SNN will be used to derive wrong keys
	ue.UeSecurity.Snn = "an unreasonable serving network name"

	msg, err := ue.WaitForNASGMMMessage(nas.MsgTypeAuthenticationReject, 200*time.Millisecond)
	if err != nil {
		return fmt.Errorf("could not receive Authentication Reject: %v", err)
	}

	err = validateAuthenticationReject(msg)
	if err != nil {
		return fmt.Errorf("could not validate Authentication Reject: %v", err)
	}

	return nil
}

func validateAuthenticationReject(nasMsg *nas.Message) error {
	if nasMsg == nil {
		return fmt.Errorf("NAS PDU is nil")
	}

	if nasMsg.GmmMessage == nil {
		return fmt.Errorf("NAS message is not a GMM message")
	}

	if nasMsg.GmmMessage.GetMessageType() != nas.MsgTypeAuthenticationReject {
		return fmt.Errorf("NAS message type is not Authentication Reject (%d), got (%d)", nas.MsgTypeAuthenticationReject, nasMsg.GmmMessage.GetMessageType())
	}

	if reflect.ValueOf(nasMsg.AuthenticationReject.ExtendedProtocolDiscriminator).IsZero() {
		return fmt.Errorf("extended protocol is missing")
	}

	if nasMsg.AuthenticationReject.GetExtendedProtocolDiscriminator() != 126 {
		return fmt.Errorf("extended protocol not the expected value")
	}

	if nasMsg.AuthenticationReject.GetSecurityHeaderType() != 0 {
		return fmt.Errorf("security header type not the expected value")
	}

	if nasMsg.AuthenticationReject.GetSpareHalfOctet() != 0 {
		return fmt.Errorf("spare half octet not the expected value")
	}

	if reflect.ValueOf(nasMsg.AuthenticationReject.AuthenticationRejectMessageIdentity).IsZero() {
		return fmt.Errorf("message type is missing")
	}

	return nil
}
