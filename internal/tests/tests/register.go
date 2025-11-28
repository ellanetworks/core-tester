package tests

import (
	"fmt"

	"github.com/ellanetworks/core-tester/internal/tests/engine"
	"github.com/ellanetworks/core-tester/internal/tests/tests/gnb"
	"github.com/ellanetworks/core-tester/internal/tests/tests/ue"
)

func RegisterAll() error {
	allTests := []engine.Test{
		gnb.SCTPBasic{},
		gnb.NGSetupResponse{},
		gnb.NGSetupFailure_UnknownPLMN{},
		gnb.NGReset{},
		ue.RegistrationReject_UnknownUE{},
		ue.RegistrationSuccess{},
		ue.RegistrationSuccess50Sequential{},
		ue.RegistrationSuccess50Parallel{},
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
		err := engine.Register(test)
		if err != nil {
			return fmt.Errorf("could not register test %T: %v", test, err)
		}
	}

	return nil
}
