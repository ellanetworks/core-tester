package main

import (
	"sync"

	"github.com/ellanetworks/core-tester/internal/config"
	"github.com/ellanetworks/core-tester/internal/gnb"
)

func main() {
	cfg := config.GetConfig()
	wg := sync.WaitGroup{}
	go gnb.InitGnb(cfg, &wg)
	wg.Add(1)
	wg.Wait()
}
