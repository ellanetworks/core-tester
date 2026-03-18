package enb

import (
	"fmt"
	"strconv"

	"github.com/ellanetworks/core-tester/internal/tests/tests/utils/core"
)

const (
	DefaultMCC                   = "001"
	DefaultMNC                   = "01"
	DefaultSST                   = 1
	DefaultSD                    = "102030"
	DefaultTAC                   = "000001"
	DefaultDNN                   = "internet"
	DefaultPolicyName            = "default"
	DefaultPolicyBitrateUplink   = "100 Mbps"
	DefaultPolicyBitrateDownlink = "100 Mbps"
	DefaultIMSI                  = "001017271246546"
	DefaultKey                   = "640f441067cd56f1474cbcacd7a0588f"
	DefaultOPC                   = "cb698a2341629c3241ae01de9d89de4f"
	DefaultSequenceNumber        = "000000000022"

	DefaultRanUENGAPID  int64 = 1
	DefaultPDUSessionID uint8 = 1
	DefaultEnbID              = "000008"

	testStartIMSI = "001017271246546"
)

func getDefaultEllaCoreConfig() core.EllaCoreConfig {
	return core.EllaCoreConfig{
		Operator: core.OperatorConfig{
			ID: core.OperatorID{
				MCC: DefaultMCC,
				MNC: DefaultMNC,
			},
			Slice: core.OperatorSlice{
				SST: DefaultSST,
				SD:  DefaultSD,
			},
			Tracking: core.OperatorTracking{
				SupportedTACs: []string{DefaultTAC},
			},
		},
		DataNetworks: []core.DataNetworkConfig{
			{
				Name:   DefaultDNN,
				IPPool: "10.45.0.0/16",
				DNS:    "8.8.8.8",
				Mtu:    1500,
			},
		},
		Policies: []core.PolicyConfig{
			{
				Name:            DefaultPolicyName,
				BitrateUplink:   DefaultPolicyBitrateUplink,
				BitrateDownlink: DefaultPolicyBitrateDownlink,
				Var5qi:          9,
				Arp:             15,
				DataNetworkName: DefaultDNN,
			},
		},
		Subscribers: []core.SubscriberConfig{
			{
				Imsi:           DefaultIMSI,
				Key:            DefaultKey,
				SequenceNumber: DefaultSequenceNumber,
				OPc:            DefaultOPC,
				PolicyName:     DefaultPolicyName,
			},
		},
	}
}

func buildSubscriberConfig(numSubscribers int, startIMSI string) ([]core.SubscriberConfig, error) {
	subs := []core.SubscriberConfig{}

	for i := range numSubscribers {
		intBaseIMSI, err := strconv.Atoi(startIMSI)
		if err != nil {
			return nil, fmt.Errorf("failed to convert base IMSI to int: %v", err)
		}

		newIMSI := intBaseIMSI + i
		imsi := fmt.Sprintf("%015d", newIMSI)

		subs = append(subs, core.SubscriberConfig{
			Imsi:           imsi,
			Key:            DefaultKey,
			SequenceNumber: DefaultSequenceNumber,
			OPc:            DefaultOPC,
			PolicyName:     DefaultPolicyName,
		})
	}

	return subs, nil
}
