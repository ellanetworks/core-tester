package tests

import (
	"fmt"

	"github.com/ellanetworks/core-tester/internal/engine"
	"github.com/ellanetworks/core-tester/tests/gnb"
)

func RegisterAll() error {
	allTests := []engine.Test{
		gnb.SCTPBasic{},
		gnb.NGSetupResponse{},
		gnb.NGSetupFailure_UnknownPLMN{},
	}

	for _, test := range allTests {
		err := engine.Register(test)
		if err != nil {
			return fmt.Errorf("could not register test %T: %v", test, err)
		}
	}

	return nil
}
