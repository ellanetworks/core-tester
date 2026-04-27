# Ella Core Tester

Ella Core Tester is a tool for validating 3GPP connectivity with [Ella Core](https://github.com/ellanetworks/core). It acts as a 5G radio (gNodeB) and User Equipment (UE) to perform a 3GPP-compliant registration against Ella Core and establish a GTP tunnel for the UE.

## Getting Started

Install dependencies:

```shell
sudo apt install libpcap-dev
```

Build the project:

```shell
go build cmd/core-tester/main.go
```

Register a subscriber and create a GTP tunnel:

```shell
sudo ./main register \
  --imsi="001010100007487" \
  --key="5122250214c33e723a5dd523fc145fc0" \
  --opc="981d464c7c52eb6e5036234984ad0bcf" \
  --sqn="000000000023" \
  --profile-name="default" \
  --mcc="001" \
  --mnc="01" \
  --sst=1 \
  --sd="102030" \
  --tac="000001" \
  --dnn="internet" \
  --gnb-n2-address="192.168.40.6" \
  --gnb-n3-address="127.0.0.1" \
  --ella-core-n2-address="192.168.40.6:38412"
```

The subscriber must already exist in Ella Core. The tester will not create or delete any resources in Ella Core. Press `Ctrl-C` to deregister the UE and tear down the tunnel.

## Reference

### CLI

Ella Core Tester provides the following commands:

- `register`: register a subscriber in Ella Core and create a GTP tunnel. The subscriber must already exist in Ella Core; the tester does not create or delete resources in Ella Core.
- `help`: display help information about Ella Core Tester or a specific command.

### Acknowledgements

Ella Core Tester could not have been possible without the following open-source projects:
- [PacketRusher](https://github.com/HewlettPackard/PacketRusher)
- [free5gc](https://github.com/free5gc/free5gc)
- [UProot](https://github.com/ghislainbourgeois/uproot)
