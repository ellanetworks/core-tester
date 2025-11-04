# Ella Core Tester

<p align="center">
  <img src="https://raw.githubusercontent.com/ellanetworks/core/main/docs/images/logo.png" alt="Ella Core Logo" width="150"/>
</p>

> :construction: **Beta Notice**
> Ella Core and Ella Core tester are currently in beta. If you encounter any issues, please [report them here](https://github.com/ellanetworks/core-tester/issues/new/choose).

Ella Core Tester is a tool for testing [Ella Core](https://github.com/ellanetworks/core)'s functionality and performance. It acts as a 5G radio (gNodeB) and User Equipment (UE), and creates a GTP-U tunnel that can be used for running performance tests.

Contrary to most 5G core simulators, Ella Core tester does not try to be a general-purpose simulator that can work with any 5G core. Instead, it is a specialized tool that is designed to quickly and easily assess the functionality and performance of Ella Core.

## Usage

Build the project:
```shell
go build cmd/core-tester/main.go
```

Create a configuration file (`config.yml`). Look at the example configuration file for details.

Run Ella Core Tester:

```shell
sudo ./main --config config.yml
```
