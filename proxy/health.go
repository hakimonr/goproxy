package proxy

import (
	"context"
	"log"
	"net"
	"sync"
	"time"
)

type HealthStatus struct {
	Host         string
	Healthy      bool
	LastCheck    time.Time
	LastError    error
	FailureCount int
}

type HealthChecker struct {
	hosts    map[string]*HealthStatus
	mu       sync.RWMutex
	interval time.Duration
}

func NewHealthChecker(interval time.Duration) *HealthChecker {
	return &HealthChecker{
		hosts:    make(map[string]*HealthStatus),
		interval: interval,
	}
}

func (hc *HealthChecker) Start(ctx context.Context) {
	if hc.interval == 0 {
		return // Health checks disabled
	}

	ticker := time.NewTicker(hc.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			hc.checkAllHosts()
		case <-ctx.Done():
			return
		}
	}
}

func (hc *HealthChecker) RegisterHost(host string) {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	if _, exists := hc.hosts[host]; !exists {
		hc.hosts[host] = &HealthStatus{
			Host:      host,
			Healthy:   true,
			LastCheck: time.Now(),
		}
	}
}

func (hc *HealthChecker) IsHealthy(host string) bool {
	hc.mu.RLock()
	defer hc.mu.RUnlock()

	status, exists := hc.hosts[host]
	if !exists {
		return true // Unknown hosts are assumed healthy
	}

	return status.Healthy
}

func (hc *HealthChecker) checkAllHosts() {
	hc.mu.RLock()
	hosts := make([]string, 0, len(hc.hosts))
	for host := range hc.hosts {
		hosts = append(hosts, host)
	}
	hc.mu.RUnlock()

	for _, host := range hosts {
		hc.checkHost(host)
	}
}

func (hc *HealthChecker) checkHost(host string) {
	// Simple TCP connection check
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}

	conn, err := dialer.Dial("tcp", host)
	
	hc.mu.Lock()
	defer hc.mu.Unlock()

	status := hc.hosts[host]
	status.LastCheck = time.Now()

	if err != nil {
		status.Healthy = false
		status.LastError = err
		status.FailureCount++
		log.Printf("[HEALTH] %s is UNHEALTHY (failures: %d): %v", host, status.FailureCount, err)
	} else {
		conn.Close()
		wasUnhealthy := !status.Healthy
		status.Healthy = true
		status.LastError = nil
		status.FailureCount = 0
		if wasUnhealthy {
			log.Printf("[HEALTH] %s is now HEALTHY", host)
		}
	}
}

func (hc *HealthChecker) RecordSuccess(host string) {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	if status, exists := hc.hosts[host]; exists {
		status.Healthy = true
		status.FailureCount = 0
	}
}

func (hc *HealthChecker) RecordFailure(host string, err error) {
	hc.mu.Lock()
	defer hc.mu.Unlock()

	if status, exists := hc.hosts[host]; exists {
		status.FailureCount++
		status.LastError = err
		if status.FailureCount >= 3 {
			status.Healthy = false
			log.Printf("[HEALTH] %s marked UNHEALTHY after %d failures", host, status.FailureCount)
		}
	}
}
