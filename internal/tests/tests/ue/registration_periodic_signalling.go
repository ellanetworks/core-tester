package ue

// type RegistrationPeriodicUpdateSignalling struct{}

// func (RegistrationPeriodicUpdateSignalling) Meta() engine.Meta {
// 	return engine.Meta{
// 		ID:      "ue/registration/periodic/signalling",
// 		Summary: "UE registration periodic test validating the Registration Request procedure for periodic update",
// 		Timeout: 2 * time.Second,
// 	}
// }

// func (t RegistrationPeriodicUpdateSignalling) Run(ctx context.Context, env engine.Env) error {
// 	ellaCoreEnv := core.NewEllaCoreEnv(env.EllaCoreClient, core.EllaCoreConfig{
// 		Operator: core.OperatorConfig{
// 			ID: core.OperatorID{
// 				MCC: env.Config.EllaCore.MCC,
// 				MNC: env.Config.EllaCore.MNC,
// 			},
// 			Slice: core.OperatorSlice{
// 				SST: env.Config.EllaCore.SST,
// 				SD:  env.Config.EllaCore.SD,
// 			},
// 			Tracking: core.OperatorTracking{
// 				SupportedTACs: []string{env.Config.EllaCore.TAC},
// 			},
// 		},
// 		DataNetworks: []core.DataNetworkConfig{
// 			{
// 				Name:   env.Config.EllaCore.DNN,
// 				IPPool: "10.45.0.0/16",
// 				DNS:    "8.8.8.8",
// 				Mtu:    1500,
// 			},
// 		},
// 		Policies: []core.PolicyConfig{
// 			{
// 				Name:            env.Config.Subscriber.PolicyName,
// 				BitrateUplink:   "100 Mbps",
// 				BitrateDownlink: "100 Mbps",
// 				Var5qi:          9,
// 				Arp:             15,
// 				DataNetworkName: env.Config.EllaCore.DNN,
// 			},
// 		},
// 		Subscribers: []core.SubscriberConfig{
// 			{
// 				Imsi:           env.Config.Subscriber.IMSI,
// 				Key:            env.Config.Subscriber.Key,
// 				SequenceNumber: env.Config.Subscriber.SequenceNumber,
// 				OPc:            env.Config.Subscriber.OPC,
// 				PolicyName:     env.Config.Subscriber.PolicyName,
// 			},
// 		},
// 	})

// 	err := ellaCoreEnv.Create(ctx)
// 	if err != nil {
// 		return fmt.Errorf("could not create EllaCore environment: %v", err)
// 	}

// 	logger.Logger.Debug("Created EllaCore environment")

// 	gNodeB, err := gnb.Start(
// 		GNBID,
// 		env.Config.EllaCore.MCC,
// 		env.Config.EllaCore.MNC,
// 		env.Config.EllaCore.SST,
// 		env.Config.EllaCore.TAC,
// 		"Ella-Core-Tester",
// 		env.Config.EllaCore.N2Address,
// 		env.Config.Gnb.N2Address,
// 	)
// 	if err != nil {
// 		return fmt.Errorf("error starting gNB: %v", err)
// 	}

// 	defer gNodeB.Close()

// 	err = gNodeB.WaitForNGSetupComplete(100 * time.Millisecond)
// 	if err != nil {
// 		return fmt.Errorf("timeout waiting for NGSetupComplete: %v", err)
// 	}

// 	newUE, err := ue.NewUE(&ue.UEOpts{
// 		Msin: env.Config.Subscriber.IMSI[5:],
// 		K:    env.Config.Subscriber.Key,
// 		OpC:  env.Config.Subscriber.OPC,
// 		Amf:  "80000000000000000000000000000000",
// 		Sqn:  env.Config.Subscriber.SequenceNumber,
// 		Mcc:  env.Config.EllaCore.MCC,
// 		Mnc:  env.Config.EllaCore.MNC,
// 		HomeNetworkPublicKey: sidf.HomeNetworkPublicKey{
// 			ProtectionScheme: "0",
// 			PublicKeyID:      "0",
// 		},
// 		RoutingIndicator: "0000",
// 		DNN:              env.Config.EllaCore.DNN,
// 		Sst:              env.Config.EllaCore.SST,
// 		Sd:               env.Config.EllaCore.SD,
// 		IMEISV:           "3569380356438091",
// 		UeSecurityCapability: utils.GetUESecurityCapability(&utils.UeSecurityCapability{
// 			Integrity: utils.IntegrityAlgorithms{
// 				Nia2: true,
// 			},
// 			Ciphering: utils.CipheringAlgorithms{
// 				Nea0: true,
// 				Nea2: true,
// 			},
// 		}),
// 	})
// 	if err != nil {
// 		return fmt.Errorf("could not create UE: %v", err)
// 	}

// 	gnbN3Address, err := netip.ParseAddr(env.Config.Gnb.N3Address)
// 	if err != nil {
// 		return fmt.Errorf("could not parse gNB N3 address: %v", err)
// 	}

// 	resp, err := procedure.InitialRegistration(ctx, &procedure.InitialRegistrationOpts{
// 		Mcc:          env.Config.EllaCore.MCC,
// 		Mnc:          env.Config.EllaCore.MNC,
// 		Sst:          env.Config.EllaCore.SST,
// 		Sd:           env.Config.EllaCore.SD,
// 		Tac:          env.Config.EllaCore.TAC,
// 		DNN:          env.Config.EllaCore.DNN,
// 		GNBID:        GNBID,
// 		RANUENGAPID:  RANUENGAPID,
// 		PDUSessionID: PDUSessionID,
// 		UE:           newUE,
// 		N3GNBAddress: gnbN3Address,
// 		GnodeB:       gNodeB,
// 		DownlinkTEID: DownlinkTEID,
// 	})
// 	if err != nil {
// 		return fmt.Errorf("InitialRegistrationProcedure failed: %v", err)
// 	}

// 	pduSessionStatus := [16]bool{}
// 	pduSessionStatus[PDUSessionID] = true

// 	err = procedure.UEContextRelease(ctx, &procedure.UEContextReleaseOpts{
// 		AMFUENGAPID:   resp.AMFUENGAPID,
// 		RANUENGAPID:   RANUENGAPID,
// 		GnodeB:        gNodeB,
// 		PDUSessionIDs: pduSessionStatus,
// 	})
// 	if err != nil {
// 		return fmt.Errorf("UEContextReleaseProcedure failed: %v", err)
// 	}

// 	nasPDU, err := ue.BuildRegistrationRequest(&ue.RegistrationRequestOpts{
// 		RegistrationType:  nasMessage.RegistrationType5GSPeriodicRegistrationUpdating,
// 		RequestedNSSAI:    nil,
// 		UplinkDataStatus:  nil,
// 		IncludeCapability: false,
// 		UESecurity:        newUE.UeSecurity,
// 		PDUSessionStatus:  &pduSessionStatus,
// 	})
// 	if err != nil {
// 		return fmt.Errorf("could not build Registration Request NAS PDU: %v", err)
// 	}

// 	encodedPdu, err := newUE.EncodeNasPduWithSecurity(nasPDU, nas.SecurityHeaderTypeIntegrityProtected)
// 	if err != nil {
// 		return fmt.Errorf("error encoding %s IMSI UE  NAS Security Mode Complete message: %v", newUE.UeSecurity.Supi, err)
// 	}

// 	err = gNodeB.SendInitialUEMessage(&gnb.InitialUEMessageOpts{
// 		Mcc:                   env.Config.EllaCore.MCC,
// 		Mnc:                   env.Config.EllaCore.MNC,
// 		GnbID:                 GNBID,
// 		Tac:                   env.Config.EllaCore.TAC,
// 		RanUENGAPID:           RANUENGAPID,
// 		NasPDU:                encodedPdu,
// 		Guti5g:                newUE.UeSecurity.Guti,
// 		RRCEstablishmentCause: ngapType.RRCEstablishmentCausePresentMoSignalling,
// 	})
// 	if err != nil {
// 		return fmt.Errorf("could not send InitialUEMessage: %v", err)
// 	}

// 	logger.Logger.Debug(
// 		"Sent Initial UE Message for Registration Request",
// 		zap.String("IMSI", newUE.UeSecurity.Supi),
// 		zap.Int64("RAN UE NGAP ID", RANUENGAPID),
// 		zap.Any("GUTI", newUE.UeSecurity.Guti),
// 	)

// 	fr, err := gNodeB.WaitForNextFrame(500 * time.Millisecond)
// 	if err != nil {
// 		return fmt.Errorf("could not receive SCTP frame: %v", err)
// 	}

// 	err = utils.ValidateSCTP(fr.Info, 60, 1)
// 	if err != nil {
// 		return fmt.Errorf("SCTP validation failed: %v", err)
// 	}

// 	_, err = validate.InitialContextSetupRequest(&validate.InitialContextSetupRequestOpts{
// 		Frame: fr,
// 	})
// 	if err != nil {
// 		return fmt.Errorf("initial context setup request validation failed: %v", err)
// 	}

// 	logger.Logger.Debug(
// 		"Received Initial Context Setup Request for Registration Periodic Update",
// 		zap.String("IMSI", newUE.UeSecurity.Supi),
// 		zap.Int64("RAN UE NGAP ID", RANUENGAPID),
// 	)

// 	err = gNodeB.SendInitialContextSetupResponse(&gnb.InitialContextSetupResponseOpts{
// 		AMFUENGAPID: resp.AMFUENGAPID,
// 		RANUENGAPID: RANUENGAPID,
// 		N3GnbIp:     gnbN3Address,
// 		PDUSessions: [16]*gnb.GnbPDUSession{
// 			{
// 				PDUSessionId: 1,
// 				DownlinkTeid: DownlinkTEID,
// 				QFI:          1,
// 			},
// 		},
// 	})
// 	if err != nil {
// 		return fmt.Errorf("could not send InitialContextSetupResponse: %v", err)
// 	}

// 	logger.Logger.Debug(
// 		"Sent Initial Context Setup Response for Registration Periodic Update",
// 		zap.String("IMSI", newUE.UeSecurity.Supi),
// 		zap.Int64("RAN UE NGAP ID", RANUENGAPID),
// 	)

// 	regComplete, err := ue.BuildRegistrationComplete(&ue.RegistrationCompleteOpts{
// 		SORTransparentContainer: nil,
// 	})
// 	if err != nil {
// 		return fmt.Errorf("could not build Registration Complete NAS PDU: %v", err)
// 	}

// 	encodedPdu, err = newUE.EncodeNasPduWithSecurity(regComplete, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered)
// 	if err != nil {
// 		return fmt.Errorf("error encoding %s IMSI UE NAS Registration Complete Msg: %v", newUE.UeSecurity.Supi, err)
// 	}

// 	err = gNodeB.SendUplinkNASTransport(&gnb.UplinkNasTransportOpts{
// 		AMFUeNgapID: resp.AMFUENGAPID,
// 		RANUeNgapID: RANUENGAPID,
// 		Mcc:         env.Config.EllaCore.MCC,
// 		Mnc:         env.Config.EllaCore.MNC,
// 		GnbID:       GNBID,
// 		Tac:         env.Config.EllaCore.TAC,
// 		NasPDU:      encodedPdu,
// 	})
// 	if err != nil {
// 		return fmt.Errorf("could not send UplinkNASTransport: %v", err)
// 	}

// 	logger.Logger.Debug(
// 		"Sent Uplink NAS Transport for Registration Complete",
// 		zap.String("IMSI", newUE.UeSecurity.Supi),
// 		zap.Int64("RAN UE NGAP ID", RANUENGAPID),
// 	)

// 	// Cleanup
// 	err = procedure.Deregistration(ctx, &procedure.DeregistrationOpts{
// 		GnodeB:      gNodeB,
// 		UE:          newUE,
// 		AMFUENGAPID: resp.AMFUENGAPID,
// 		RANUENGAPID: RANUENGAPID,
// 		MCC:         env.Config.EllaCore.MCC,
// 		MNC:         env.Config.EllaCore.MNC,
// 		GNBID:       GNBID,
// 		TAC:         env.Config.EllaCore.TAC,
// 	})
// 	if err != nil {
// 		return fmt.Errorf("DeregistrationProcedure failed: %v", err)
// 	}

// 	err = ellaCoreEnv.Delete(ctx)
// 	if err != nil {
// 		return fmt.Errorf("could not delete EllaCore environment: %v", err)
// 	}

// 	logger.Logger.Debug("Deleted EllaCore environment")

// 	return nil
// }
