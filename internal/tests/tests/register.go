package tests

import (
	"fmt"

	"github.com/ellanetworks/core-tester/internal/tests/engine"
	"github.com/ellanetworks/core-tester/internal/tests/tests/gnb"
	"github.com/ellanetworks/core-tester/internal/tests/tests/ue"
)

func RegisterAll(labEnv bool) error {
	allTests := []engine.Test{
		gnb.SCTPBasic{},
		gnb.NGSetupResponse{},
		gnb.NGSetupFailure_UnknownPLMN{},
		gnb.NGReset{},
		ue.RegistrationReject_UnknownUE{},
		ue.RegistrationSuccess{},
		ue.RegistrationSuccessV4V6{},
		ue.RegistrationSuccess50Sequential{},
		ue.RegistrationSuccess150Parallel{},
		ue.RegistrationSuccessMultiplePolicies{},
		ue.RegistrationSuccessMultipleDataNetworks{},
		ue.RegistrationSuccessProfileA{},
		ue.RegistrationRejectInvalidHomeNetworkPublicKey{},
		ue.RegistrationSuccessNoSD{},
		ue.AuthenticationWrongKey{},
		ue.RegistrationPeriodicUpdateSignalling{},
		ue.RegistrationIncorrectGUTI{},
		ue.Deregistration{},
		ue.UEContextRelease{},
		ue.ServiceRequestData{},
		ue.Connectivity{},
		ue.DownlinkDataPaging{},
	}

	for _, test := range allTests {
		// Skip lab-only tests if not in lab environment
		if !labEnv && test.Meta().Environment == "lab" {
			continue
		}

		err := engine.Register(test)
		if err != nil {
			return fmt.Errorf("could not register test %T: %v", test, err)
		}
	}

	return nil
}
