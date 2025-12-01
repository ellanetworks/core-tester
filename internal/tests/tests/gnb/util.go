package gnb

import "github.com/ellanetworks/core-tester/internal/tests/tests/utils/core"

const (
	DefaultMCC = "001"
	DefaultMNC = "01"
	DefaultSST = 1
	DefaultSD  = "102030"
	DefaultTAC = "000001"
	DefaultDNN = "internet"
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
	}
}
