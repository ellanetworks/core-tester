package tests

import (
	"fmt"

	"github.com/ellanetworks/core-tester/internal/engine"
	"github.com/ellanetworks/core-tester/tests/gnb"
)

func RegisterAll() error {
	err := engine.Register(gnb.RegistrationBasic{})
	if err != nil {
		return fmt.Errorf("could not register gnb/sctp/basic test: %v", err)
	}

	return nil
}
