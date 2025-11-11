# Ella Core Tester

<p align="center">
  <img src="https://raw.githubusercontent.com/ellanetworks/core/main/docs/images/logo.png" alt="Ella Core Logo" width="150"/>
</p>

> :construction: **Beta Notice**
> Ella Core and Ella Core tester are currently in beta. If you encounter any issues, please [report them here](https://github.com/ellanetworks/core-tester/issues/new/choose).

Ella Core Tester is a tool for testing [Ella Core](https://github.com/ellanetworks/core)'s functionality, reliability, and performance. It acts as a 5G radio (gNodeB) and User Equipment (UE) to simulate real-world 3GPP-compliant interactions between the radio/UE and Ella Core.

## Getting Started

Build the project:
```shell
go build cmd/core-tester/main.go
```

Create a configuration file (`config.yml`). Look at the example configuration under `config/config.yaml` and modify it to fit your Ella Core instance.

Run all tests:

```shell
./main test --config config.yml
```

Example output:

```shell
guillaume@courge:~/code/core-tester$ ./main test --config config.yml
PASSED  gnb/sctp  (2ms)
PASSED  gnb/ngap/setup_failure/unknown_plmn  (1ms)
PASSED  gnb/ngap/reset  (1ms)
PASSED  ue/registration/incorrect_guti  (366ms)
PASSED  ue/deregistration  (644ms)
PASSED  ue/context/release  (669ms)
PASSED  ue/service_request/data  (874ms)
PASSED  gnb/ngap/setup_response  (1ms)
PASSED  ue/registration_reject/unknown_ue  (228ms)
PASSED  ue/registration_success  (668ms)
PASSED  ue/authentication/wrong_key  (234ms)
PASSED  ue/registration/periodic/signalling  (1.061s)
```

## How-to Guides

## Add a new test

To add a new test, follow these steps:

1. Create a new .go file in the `tests/gnb/` or `tests/ue/` directory depending on the type of test.
2. Define a new struct that implements the `engine.Test` interface.
3. Implement the `Meta()` method to provide metadata about the test.
4. Implement the `Run()` method to define the test logic.
5. Register the test in the `tests/register.go` file.

> Note: Use the existing tests as references for how to structure your test.

## Reference

### CLI

Ella Core Tester provides a command-line interface (CLI) with the following commands:

- `test`: run all the available tests against the Ella Core instance specified in the configuration file. This command is useful for testing Ella Core's functionality. You can optionally specify an output file to write the test results in JSON format. This command will modify the state of Ella Core by creating and deleting subscribers and sessions.
- `register`: register a subscriber in Ella Core and create a GTP tunnel. This command is useful to validate connectivity with the private network. The subscriber needs to already be created in Ella Core. This procedure will not try to create and delete resources in Ella Core.
- `help`: display help information about Ella Core Tester or a specific command.

### Acknowledgements

Ella Core tester could not have been possible without the following open-source projects:
- [PacketRusher](https://github.com/HewlettPackard/PacketRusher)
- [free5gc](https://github.com/free5gc/free5gc)
- [UProot](https://github.com/ghislainbourgeois/uproot)
