package monitoring

import (
	"sync"
)

type Monitor struct {
	mu               sync.Mutex
	RqsG             int64
	RqsL             int64
	pcktLoss         int64
	LtRegisterLocal  int64
	LtRegisterGlobal int64
	availability     bool
}

func (m *Monitor) IncRqs() {
	m.mu.Lock()
	m.RqsL++
	m.mu.Unlock()
}

func (m *Monitor) IncPcktLoss() {
	m.mu.Lock()
	m.pcktLoss++
	m.mu.Unlock()
}

func (m *Monitor) IncAvaibility() {
	m.mu.Lock()
	m.availability = true
	m.mu.Unlock()
}

func (m *Monitor) InitRqsLocal() {
	m.RqsL = 0
}

func (m *Monitor) InitAvaibility() {
	m.availability = false
}

// calcula o número de requests em um intervalo
func (m *Monitor) SetRqsGlobal(rqs int64) {
	m.RqsG += rqs
}

func (m *Monitor) GetRqsLocal() int64 {
	return m.RqsL
}

func (m *Monitor) GetRqsGlobal() int64 {
	return m.RqsG
}

func (m *Monitor) GetAvailability() bool {
	return m.availability
}
