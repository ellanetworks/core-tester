package main

import (
	"os"

	"github.com/davecgh/go-spew/spew"
	"github.com/ellanetworks/core-tester/internal/config"
	"github.com/ellanetworks/core-tester/internal/templates"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

const version = "1.0.1"

func init() {
	spew.Config.Indent = "\t"
}

func main() {
	app := &cli.App{
		Flags: []cli.Flag{
			&cli.PathFlag{Name: "config", Usage: "Configuration file path. (Default: ./internal/config/config.yml)"},
		},
		Commands: []*cli.Command{
			{
				Name:    "multi-ue-pdu",
				Aliases: []string{"multi-ue"},
				Usage: "\nLoad endurance stress tests.\n" +
					"Example for testing multiple UEs: multi-ue -n 5 \n" +
					"This test case will launch N UEs. See packetrusher multi-ue --help\n",
				Flags: []cli.Flag{
					&cli.IntFlag{Name: "number-of-ues", Value: 1, Aliases: []string{"n"}},
					&cli.IntFlag{Name: "timeBetweenRegistration", Value: 500, Aliases: []string{"tr"}, Usage: "The time in ms, between UE registration."},
					&cli.IntFlag{Name: "timeBeforeDeregistration", Value: 0, Aliases: []string{"td"}, Usage: "The time in ms, before a UE deregisters once it has been registered. 0 to disable auto-deregistration."},
					&cli.IntFlag{Name: "timeBeforeNgapHandover", Value: 0, Aliases: []string{"ngh"}, Usage: "The time in ms, before triggering a UE handover using NGAP Handover. 0 to disable handover. This requires at least two gNodeB, eg: two N2/N3 IPs."},
					&cli.IntFlag{Name: "timeBeforeXnHandover", Value: 0, Aliases: []string{"xnh"}, Usage: "The time in ms, before triggering a UE handover using Xn Handover. 0 to disable handover. This requires at least two gNodeB, eg: two N2/N3 IPs."},
					&cli.IntFlag{Name: "timeBeforeIdle", Value: 0, Aliases: []string{"idl"}, Usage: "The time in ms, before switching UE to Idle. 0 to disable Idling."},
					&cli.IntFlag{Name: "timeBeforeReconnecting", Value: 1000, Aliases: []string{"tbr"}, Usage: "The time in ms, before reconnecting to gNodeB after switching to Idle state. Default is 1000 ms. Only work in conjunction with timeBeforeIdle."},
					&cli.IntFlag{Name: "numPduSessions", Value: 1, Aliases: []string{"nPdu"}, Usage: "The number of PDU Sessions to create"},
					&cli.BoolFlag{Name: "loop", Aliases: []string{"l"}, Usage: "Register UEs in a loop."},
					&cli.IntFlag{Name: "loopCount", Value: 0, Aliases: []string{"lc"}, Usage: "The number of times the loop is executed. 0 to loop infinitely."},
					&cli.IntFlag{Name: "timeBeforeReregistration", Value: 200, Aliases: []string{"tbrr"}, Usage: "The time in ms before the UE registers again after deregistration if UE is looping."},
					&cli.BoolFlag{Name: "tunnel", Aliases: []string{"t"}, Usage: "Enable the creation of the GTP-U tunnel interface."},
					&cli.BoolFlag{Name: "tunnel-vrf", Value: true, Usage: "Enable/disable VRP usage of the GTP-U tunnel interface."},
					&cli.BoolFlag{Name: "dedicatedGnb", Aliases: []string{"d"}, Usage: "Enable the creation of a dedicated gNB per UE. Require one IP on N2/N3 per gNB."},
					&cli.PathFlag{Name: "pcap", Usage: "Capture traffic to given PCAP file when a path is given", Value: "./dump.pcap"},
				},
				Action: func(c *cli.Context) error {
					var numUes int
					name := "Testing registration of multiple UEs"
					cfg := setConfig(*c)
					if c.IsSet("number-of-ues") {
						numUes = c.Int("number-of-ues")
					} else {
						log.Info(c.Command.Usage)
						return nil
					}

					log.Info("PacketRusher version " + version)
					log.Info("---------------------------------------")
					log.Info("[TESTER] Starting test function: ", name)
					log.Info("[TESTER][UE] Number of UEs: ", numUes)
					log.Info("[TESTER][GNB] gNodeB control interface IP/Port: ", cfg.GNodeB.ControlIF.AddrPort, "~")
					log.Info("[TESTER][GNB] gNodeB data interface IP/Port: ", cfg.GNodeB.DataIF.AddrPort)
					for _, amf := range cfg.AMFs {
						log.Info("[TESTER][AMF] AMF IP/Port: ", amf.AddrPort)
					}
					log.Info("---------------------------------------")

					tunnelMode := config.TunnelDisabled
					if c.Bool("tunnel") {
						if c.Bool("tunnel-vrf") {
							tunnelMode = config.TunnelVrf
						} else {
							tunnelMode = config.TunnelTun
						}
					}
					templates.TestMultiUesInQueue(numUes, tunnelMode, c.Bool("dedicatedGnb"), c.Bool("loop"), c.Int("loopCount"), c.Int("timeBeforeReregistration"), c.Int("timeBetweenRegistration"), c.Int("timeBeforeDeregistration"), c.Int("timeBeforeNgapHandover"), c.Int("timeBeforeXnHandover"), c.Int("timeBeforeIdle"), c.Int("timeBeforeReconnecting"), c.Int("numPduSessions"))

					return nil
				},
			},
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func setConfig(c cli.Context) config.Config {
	var cfg config.Config
	if c.IsSet("config") {
		cfg = config.Load(c.Path("config"))
	} else {
		cfg = config.LoadDefaultConfig()
	}
	return cfg
}
