package ue

import (
	"context"
	"fmt"
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
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
	"go.uber.org/zap"
)

type RegistrationReject_UnknownUE struct{}

func (RegistrationReject_UnknownUE) Meta() engine.Meta {
	return engine.Meta{
		ID:      "ue/registration_reject/unknown_ue",
		Summary: "UE registration reject test for unknown UE",
		Timeout: 2 * time.Second,
	}
}

func (t RegistrationReject_UnknownUE) Run(ctx context.Context, env engine.Env) error {
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
		env.Config.Gnb.N3Address,
	)
	if err != nil {
		return fmt.Errorf("error starting gNB: %v", err)
	}

	defer gNodeB.Close()

	_, err = gNodeB.WaitForMessage(ngapType.NGAPPDUPresentSuccessfulOutcome, ngapType.SuccessfulOutcomePresentNGSetupResponse, 200*time.Millisecond)
	if err != nil {
		return fmt.Errorf("timeout waiting for NGSetupComplete: %v", err)
	}

	secCap := utils.UeSecurityCapability{
		Integrity: utils.IntegrityAlgorithms{
			Nia2: true,
		},
		Ciphering: utils.CipheringAlgorithms{
			Nea0: true,
			Nea2: true,
		},
	}

	newUEOpts := &ue.UEOpts{
		GnodeB: gNodeB,
		Msin:   "1234567890", // Unknown MSIN
		K:      env.Config.Subscriber.Key,
		OpC:    env.Config.Subscriber.OPC,
		Amf:    "80000000000000000000000000000000",
		Sqn:    env.Config.Subscriber.SequenceNumber,
		Mcc:    env.Config.EllaCore.MCC,
		Mnc:    env.Config.EllaCore.MNC,
		HomeNetworkPublicKey: sidf.HomeNetworkPublicKey{
			ProtectionScheme: "0",
			PublicKeyID:      "0",
		},
		RoutingIndicator:     "0000",
		DNN:                  env.Config.EllaCore.DNN,
		Sst:                  env.Config.EllaCore.SST,
		Sd:                   env.Config.EllaCore.SD,
		UeSecurityCapability: utils.GetUESecurityCapability(&secCap),
	}

	newUE, err := ue.NewUE(newUEOpts)
	if err != nil {
		return fmt.Errorf("could not create UE: %v", err)
	}

	gNodeB.AddUE(RANUENGAPID, newUE)

	err = newUE.SendRegistrationRequest(RANUENGAPID, nasMessage.RegistrationType5GSInitialRegistration)
	if err != nil {
		return fmt.Errorf("could not send Registration Request: %v", err)
	}

	fr, err := gNodeB.WaitForMessage(ngapType.NGAPPDUPresentInitiatingMessage, ngapType.InitiatingMessagePresentDownlinkNASTransport, 200*time.Millisecond)
	if err != nil {
		return fmt.Errorf("timeout waiting for NGSetupComplete: %v", err)
	}

	err = utils.ValidateSCTP(fr.Info, 60, 1)
	if err != nil {
		return fmt.Errorf("SCTP validation failed: %v", err)
	}

	pdu, err := ngap.Decoder(fr.Data)
	if err != nil {
		return fmt.Errorf("could not decode NGAP: %v", err)
	}

	if pdu.InitiatingMessage == nil {
		return fmt.Errorf("NGAP PDU is not a InitiatingMessage")
	}

	if pdu.InitiatingMessage.ProcedureCode.Value != ngapType.ProcedureCodeDownlinkNASTransport {
		return fmt.Errorf("NGAP ProcedureCode is not DownlinkNASTransport (%d)", ngapType.ProcedureCodeDownlinkNASTransport)
	}

	downlinkNASTransport := pdu.InitiatingMessage.Value.DownlinkNASTransport
	if downlinkNASTransport == nil {
		return fmt.Errorf("DownlinkNASTransport is nil")
	}

	receivedNASPDU := utils.GetNASPDUFromDownlinkNasTransport(downlinkNASTransport)

	if receivedNASPDU == nil {
		return fmt.Errorf("could not get NAS PDU from DownlinkNASTransport")
	}

	err = validateRegistrationReject(receivedNASPDU, newUE, nasMessage.Cause5GMMUEIdentityCannotBeDerivedByTheNetwork)
	if err != nil {
		return fmt.Errorf("NAS PDU validation failed: %v", err)
	}

	logger.Logger.Debug(
		"Received Registration Reject",
		zap.String("IMSI", newUE.UeSecurity.Supi),
		zap.String("Cause", "UE Identity Cannot Be Derived By The Network"),
	)

	// Cleanup
	err = ellaCoreEnv.Delete(ctx)
	if err != nil {
		return fmt.Errorf("could not delete EllaCore environment: %v", err)
	}

	logger.Logger.Debug("Deleted EllaCore environment")

	return nil
}

func validateRegistrationReject(nasPDU *ngapType.NASPDU, ue *ue.UE, cause uint8) error {
	if nasPDU == nil {
		return fmt.Errorf("NAS PDU is nil")
	}

	msg, err := ue.DecodeNAS(nasPDU.Value)
	if err != nil {
		return fmt.Errorf("could not decode NAS PDU: %v", err)
	}

	if msg == nil {
		return fmt.Errorf("NAS message is nil")
	}

	if msg.GmmMessage == nil {
		return fmt.Errorf("NAS message is not a GMM message")
	}

	if msg.GmmMessage.GetMessageType() != nas.MsgTypeRegistrationReject {
		return fmt.Errorf("NAS message type is not Registration Reject (%d), got (%d)", nas.MsgTypeRegistrationReject, msg.GmmMessage.GetMessageType())
	}

	if msg.RegistrationReject == nil {
		return fmt.Errorf("NAS Registration Reject message is nil")
	}

	if msg.RegistrationReject.GetCauseValue() != cause {
		return fmt.Errorf("NAS Registration Reject Cause is not Unknown UE (%x), received (%x)", cause, msg.RegistrationReject.GetCauseValue())
	}

	return nil
}
