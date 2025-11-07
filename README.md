# Ella Core Tester

<p align="center">
  <img src="https://raw.githubusercontent.com/ellanetworks/core/main/docs/images/logo.png" alt="Ella Core Logo" width="150"/>
</p>

> :construction: **Beta Notice**
> Ella Core and Ella Core tester are currently in beta. If you encounter any issues, please [report them here](https://github.com/ellanetworks/core-tester/issues/new/choose).

Ella Core Tester is a tool for testing [Ella Core](https://github.com/ellanetworks/core)'s functionality, reliability, and performance. It acts as a 5G radio (gNodeB) and User Equipment (UE) to simulate real-world 3GPP-compliant interactions between the radio/UE and Ella Core.

## Usage

Build the project:
```shell
go build cmd/core-tester/main.go
```

Create a configuration file (`config.yml`). Look at the example configuration file for details.

Run Ella Core Tester:

```shell
sudo ./main --config config.yml -write results.json
```

Example output:

```shell
guillaume@courge:~/code/core-tester$ go run cmd/core-tester/main.go --config config.yml
gnb/sctp                             PASSED    (15ms)
gnb/ngap/setup_failure/unknown_plmn  PASSED    (1ms)
ue/registration_reject/unknown_ue    PASSED    (3ms)
ue/registration/periodic/signalling  PASSED    (841ms)
ue/registration/periodic/data        PASSED    (844ms)
gnb/ngap/setup_response              PASSED    (1ms)
gnb/ngap/reset                       PASSED    (2ms)
ue/registration_success              PASSED    (421ms)
ue/deregistration                    PASSED    (426ms)
ue/context/release                   PASSED    (432ms)
```

## How-to add a new test

To add a new test, follow these steps:

1. Create a new .go file in the `tests/gnb/` or `tests/ue/` directory depending on the type of test.
2. Define a new struct that implements the `engine.Test` interface.
3. Implement the `Meta()` method to provide metadata about the test.
4. Implement the `Run()` method to define the test logic.
5. Register the test in the `tests/register.go` file.

> Note: Use the existing tests as references for how to structure your test.

## Acknowledgements

Ella Core tester could not have been possible without the following open-source projects:
- [PacketRusher](https://github.com/HewlettPackard/PacketRusher)
- [free5gc](https://github.com/free5gc/free5gc)
- [UProot](https://github.com/ghislainbourgeois/uproot)
