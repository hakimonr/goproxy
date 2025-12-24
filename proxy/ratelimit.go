package proxy

import (
	"log"
	"sync"
	"time"
)

type AdaptiveThrottler struct {
	BaseDelay     time.Duration
	CurrentDelay  time.Duration
	ErrorCount    int
	SuccessCount  int
	mutex         sync.Mutex
}

func NewAdaptiveThrottler(baseDelay time.Duration) *AdaptiveThrottler {
	return &AdaptiveThrottler{
		BaseDelay:    baseDelay,
		CurrentDelay: baseDelay,
	}
}

func (a *AdaptiveThrottler) AdjustDelay(statusCode int, responseTime time.Duration, retryAfter string, strictMode bool) {
	if strictMode {
		return // No adjustment in strict mode
	}
	
	a.mutex.Lock()
	defer a.mutex.Unlock()
	
	if statusCode == 429 {
		// Rate limit detected
		log.Printf("[RATE LIMIT] 429 detected, increasing delay")
		
		// Check for Retry-After header
		if retryAfter != "" {
			// Try to parse as seconds
			if seconds, err := time.ParseDuration(retryAfter + "s"); err == nil {
				a.CurrentDelay = seconds
				log.Printf("[RATE LIMIT] Using Retry-After: %v", seconds)
				a.ErrorCount++
				return
			}
		}
		
		// No Retry-After or parse failed, double the delay
		a.CurrentDelay = a.CurrentDelay * 2
		a.ErrorCount++
		log.Printf("[RATE LIMIT] Doubled delay to %v", a.CurrentDelay)
		
	} else if statusCode >= 500 {
		// Server error, increase delay
		a.CurrentDelay = a.CurrentDelay * 2
		a.ErrorCount++
	} else if statusCode >= 200 && statusCode < 300 {
		// Successful response, gradually decrease delay
		a.SuccessCount++
		if a.CurrentDelay > a.BaseDelay {
			a.CurrentDelay = time.Duration(float64(a.CurrentDelay) * 0.9)
			if a.CurrentDelay < a.BaseDelay {
				a.CurrentDelay = a.BaseDelay
			}
		}
	}
}

func (a *AdaptiveThrottler) GetCurrentDelay() time.Duration {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	return a.CurrentDelay
}

// Update the applyRateLimit method to support different throttle modes
func (p *ProxyServer) applyRateLimitWithMode() {
	// Handle delay limiting FIRST (before acquiring semaphore)
	if p.DelayMs > 0 {
		var delay time.Duration

		switch p.ThrottleMode {
		case "adaptive":
			// For now, use simple adaptive throttling based on configuration
			delay = time.Duration(p.DelayMs) * time.Millisecond
		case "sequential":
			fallthrough
		default:
			// Standard delay based on configuration
			delay = time.Duration(p.DelayMs) * time.Millisecond
		}

		// Apply delay between requests
		p.mu.Lock()
		elapsed := time.Since(p.lastRequestTime)

		if elapsed < delay {
			sleepTime := delay - elapsed
			log.Printf("[THROTTLE] Sleeping for %v", sleepTime)
			time.Sleep(sleepTime)
		}

		p.lastRequestTime = time.Now()
		p.mu.Unlock()
	}

	// Handle concurrency limiting AFTER timing
	if p.MaxConcurrent > 0 {
		// Acquire semaphore (concurrency control) only if limiting is enabled
		p.requestSemaphore <- struct{}{}
		defer func() { <-p.requestSemaphore }()
	}
}