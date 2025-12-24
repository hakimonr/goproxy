package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

type RequestStat struct {
	TotalRequests    int64
	HTTPRequests     int64
	HTTPSRequests    int64
	StartTime        time.Time
	Mutex            sync.Mutex
}

type CircuitBreaker struct {
	failures         map[string]int
	lastFailureTime  map[string]time.Time
	threshold        int
	timeout          time.Duration
	mu               sync.RWMutex
}

func NewCircuitBreaker(threshold int, timeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		failures:        make(map[string]int),
		lastFailureTime: make(map[string]time.Time),
		threshold:       threshold,
		timeout:         timeout,
	}
}

func (cb *CircuitBreaker) RecordSuccess(host string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	delete(cb.failures, host)
	delete(cb.lastFailureTime, host)
}

func (cb *CircuitBreaker) RecordFailure(host string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures[host]++
	cb.lastFailureTime[host] = time.Now()
}

func (cb *CircuitBreaker) IsOpen(host string) bool {
	if cb.threshold == 0 {
		return false // Circuit breaker disabled
	}
	
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	
	failures := cb.failures[host]
	if failures < cb.threshold {
		return false
	}
	
	// Check if timeout has passed
	lastFailure := cb.lastFailureTime[host]
	if time.Since(lastFailure) > cb.timeout {
		// Timeout passed, allow retry
		return false
	}
	
	return true
}

type ProxyServer struct {
	ListenAddr           string
	MaxConcurrent        int
	DelayMs              int
	TargetScope          *regexp.Regexp
	TLSConfig            *tls.Config
	DisableSSLVerify     bool
	UpstreamProxy        string
	ThrottleMode         string
	StrictThrottle       bool
	requestSemaphore     chan struct{}
	lastRequestTime      time.Time
	mu                   sync.Mutex
	server               *http.Server
	RequestStat          *RequestStat
	LogWriter            io.Writer
	Logger               *Logger
	LogRequestBody       bool
	LogResponseBody      bool
	LogRequestHeaders    bool
	LogResponseHeaders   bool
	ExcludeContentTypes  []string
	ExcludeExtensions    []string
	MaxLogBodySize       int64
	StructuredLogging    bool
	HTTPClient           *http.Client
	// Retry logic
	MaxRetries           int
	RetryDelayMs         int
	// Circuit breaker
	CircuitBreaker       *CircuitBreaker
	// Timeouts
	ConnectTimeout       time.Duration
	TLSTimeout           time.Duration
	RequestTimeout       time.Duration
	IdleTimeout          time.Duration
	// Adaptive throttling
	AdaptiveThrottler    *AdaptiveThrottler
	// Advanced statistics
	AdvancedStats        *AdvancedStats
	// Memory limits
	MaxResponseSize      int64
	// Health checker
	HealthChecker        *HealthChecker
}

func (p *ProxyServer) Start(ctx context.Context) error {
	// Initialize semaphore for concurrency control only if needed
	if p.MaxConcurrent > 0 {
		p.requestSemaphore = make(chan struct{}, p.MaxConcurrent)
	} else {
		// If no concurrency limit, make the channel large enough to never block
		p.requestSemaphore = make(chan struct{}, 1000) // Use a large number as effective "unlimited"
	}

	// Initialize request statistics
	p.RequestStat = &RequestStat{
		TotalRequests: 0,
		HTTPRequests:  0,
		HTTPSRequests: 0,
		StartTime:     time.Now(),
	}

	// Initialize the enhanced logger if log writer is provided
	if p.LogWriter != nil {
		// Extract the log file path from the writer if possible
		logPath := "proxy.log" // default
		if p.LogWriter != nil {
			// Best effort to determine log path - in a real implementation you might want to pass this explicitly
			logPath = "proxy.log"
		}
		logger, err := NewLogger(logPath, 10) // 10MB max size
		if err != nil {
			log.Printf("[ERROR] Failed to initialize logger: %v", err)
		} else {
			p.Logger = logger
		}
	}

	// Initialize HTTP client for forwarding
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: p.DisableSSLVerify,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	// If upstream proxy is specified, configure it
	if p.UpstreamProxy != "" {
		proxyURL, err := url.Parse(p.UpstreamProxy)
		if err != nil {
			log.Printf("[ERROR] Invalid upstream proxy URL: %v", err)
		} else {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	p.HTTPClient = &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	// Start periodic logging
	go p.startPeriodicLogging(ctx)

	p.server = &http.Server{
		Addr:    p.ListenAddr,
		Handler: http.HandlerFunc(p.handleRequest),
	}

	// Start the server in a goroutine
	errChan := make(chan error, 1)
	go func() {
		if err := p.server.ListenAndServe(); err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	// Wait for context cancellation or server error
	select {
	case err := <-errChan:
		// Close the logger if it was initialized
		if p.Logger != nil {
			p.Logger.Close()
		}
		return err
	case <-ctx.Done():
		// Context was cancelled, shut down gracefully
		err := p.server.Shutdown(context.Background())
		// Close the logger if it was initialized
		if p.Logger != nil {
			p.Logger.Close()
		}
		return err
	}
}

func (p *ProxyServer) startPeriodicLogging(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Capture stats while holding the mutex
			p.RequestStat.Mutex.Lock()
			totalRequests := p.RequestStat.TotalRequests
			httpRequests := p.RequestStat.HTTPRequests
			httpsRequests := p.RequestStat.HTTPSRequests
			startTime := p.RequestStat.StartTime
			p.RequestStat.Mutex.Unlock()

			// Calculate uptime
			uptime := time.Since(startTime)
			avgRequestsPerMinute := float64(totalRequests) / (float64(uptime.Seconds()) / 60.0)
			if uptime.Seconds() < 60 {
				avgRequestsPerMinute = float64(totalRequests) // If less than 1 minute, just show the total
			}

			log.Printf("[PROGRESS] Proxy running for %v | Total requests: %d | HTTP: %d | HTTPS: %d | Avg: %.2f req/min",
				uptime.Round(time.Second), totalRequests, httpRequests, httpsRequests, avgRequestsPerMinute)
			
			// Log advanced statistics summary every 5 minutes
			if int(uptime.Minutes())%5 == 0 && uptime.Seconds() > 60 {
				if p.AdvancedStats != nil {
					log.Printf("%s", p.AdvancedStats.GetSummary())
				}
			}
		case <-ctx.Done():
			// Context cancelled, exit the goroutine
			return
		}
	}
}

// logDetailed writes detailed logs directly to the file without going through the console filter
func (p *ProxyServer) logDetailed(format string, args ...interface{}) {
	if p.Logger != nil {
		p.Logger.LogAsGoProxyFormat(format, args...)
	} else if p.LogWriter != nil {
		logLine := fmt.Sprintf(format, args...)
		timestamp := time.Now().Format("2006/01/02 15:04:05")
		output := fmt.Sprintf("%s %s\n", timestamp, logLine)
		p.LogWriter.Write([]byte(output))
	}
}

func (p *ProxyServer) handleRequest(w http.ResponseWriter, r *http.Request) {
	// Update statistics
	p.RequestStat.Mutex.Lock()
	p.RequestStat.TotalRequests++
	if r.Method == http.MethodConnect {
		p.RequestStat.HTTPSRequests++
	} else {
		p.RequestStat.HTTPRequests++
	}
	p.RequestStat.Mutex.Unlock()

	// Check if request is CONNECT (HTTPS tunneling)
	if r.Method == http.MethodConnect {
		p.handleHTTPS(w, r)
		return
	}

	// HTTP request
	p.handleHTTP(w, r)
}

// isTextContent checks if the content is likely to be text based on content-type and content itself
func (p *ProxyServer) isTextContent(contentType string, content []byte) bool {
	// Check Content-Type header
	if contentType != "" {
		// Common text content types
		textTypes := []string{"text/", "application/json", "application/xml", "application/x-www-form-urlencoded", "application/javascript", "application/ecmascript", "multipart/form-data"}
		for _, textType := range textTypes {
			if strings.Contains(strings.ToLower(contentType), textType) {
				return true
			}
		}

		// Explicitly exclude binary content types
		binaryTypes := []string{"application/octet-stream", "application/zip", "application/x-zip",
			"application/gzip", "application/x-gzip", "application/x-tar", "application/x-rar-compressed",
			"application/pdf", "application/msword", "application/vnd.ms-excel",
			"application/vnd.openxmlformats-officedocument", "image/", "video/", "audio/",
			"application/x-shockwave-flash", "application/font", "font/"}
		for _, binaryType := range binaryTypes {
			if strings.Contains(strings.ToLower(contentType), binaryType) {
				return false
			}
		}
	}

	// Check for common binary file signatures (magic bytes)
	if p.hasBinarySignature(content) {
		return false
	}

	// Even if Content-Type isn't text, check if the content looks like text
	// Check the first 1000 bytes to see if it's mostly printable characters
	checkLen := len(content)
	if checkLen > 1000 {
		checkLen = 1000
	}

	textChars := 0
	nullByteCount := 0
	for i := 0; i < checkLen; i++ {
		b := content[i]
		// Count null bytes which are common in binary files
		if b == 0 {
			nullByteCount++
		}
		// Printable ASCII characters, tab, newline, carriage return
		if (b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13 {
			textChars++
		}
	}

	// If more than 10% of the content consists of null bytes, it's likely binary
	if float64(nullByteCount)/float64(checkLen) > 0.1 {
		return false
	}

	// If more than 80% of the content looks like text, consider it text
	return float64(textChars)/float64(checkLen) > 0.8
}

// hasBinarySignature checks for common binary file signatures (magic bytes)
func (p *ProxyServer) hasBinarySignature(content []byte) bool {
	if len(content) < 4 {
		return false
	}

	// Common binary file signatures
	signatures := [][]byte{
		{0x1f, 0x8b},                   // gzip
		{0x50, 0x4b},                   // zip
		{0x52, 0x61, 0x72, 0x21},      // rar
		{0x25, 0x50, 0x44, 0x46},      // pdf
		{0x89, 0x50, 0x4e, 0x47},      // png
		{0xff, 0xd8, 0xff},             // jpg
		{0x47, 0x49, 0x46},             // gif
		{0x42, 0x4d},                   // bmp
		{0x49, 0x49, 0x2a, 0x00},      // tiff (little endian)
		{0x4d, 0x4d, 0x00, 0x2a},      // tiff (big endian)
		{0x49, 0x44, 0x33},             // mp3
		{0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70}, // mp4
		{0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70}, // mp4
		{0x52, 0x49, 0x46, 0x46},      // webp, wav
		{0x4f, 0x67, 0x67, 0x53},      // ogg
	}

	for _, sig := range signatures {
		if len(content) >= len(sig) {
			match := true
			for i, b := range sig {
				if content[i] != b {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}

	return false
}

// shouldLogContent determines whether content should be logged based on content type, file extension, and size
func (p *ProxyServer) shouldLogContent(contentType string, url string) bool {
	// Check if content type should be excluded
	for _, excludedType := range p.ExcludeContentTypes {
		excludedType = strings.TrimSpace(excludedType)
		if excludedType == "" {
			continue
		}
		// Handle wildcard matching like "image/*"
		if strings.HasSuffix(excludedType, "/*") {
			baseType := strings.TrimSuffix(excludedType, "/*")
			if strings.HasPrefix(strings.ToLower(contentType), strings.ToLower(baseType)) {
				return false
			}
		} else if strings.Contains(strings.ToLower(contentType), strings.ToLower(excludedType)) {
			return false
		}
	}

	// Check if file extension should be excluded
	for _, excludedExt := range p.ExcludeExtensions {
		excludedExt = strings.TrimSpace(excludedExt)
		if excludedExt == "" {
			continue
		}
		if strings.HasSuffix(strings.ToLower(url), excludedExt) {
			return false
		}
	}

	return true
}

// Add to ProxyServer struct
func (p *ProxyServer) createDiagnosticTLSConfig() *tls.Config {
    if p.TLSConfig == nil {
        log.Printf("[ERROR] TLSConfig is nil, cannot clone")
        return nil
    }

    config := p.TLSConfig.Clone()

    // Add callback to log client hello - but only if not already set by cert loader
    if config.GetConfigForClient == nil {
        config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
            log.Printf("[TLS DEBUG] Client Hello from %s:", hello.Conn.RemoteAddr())
            log.Printf("  Server Name: %s", hello.ServerName)
            log.Printf("  Supported Versions: %v", hello.SupportedVersions)
            log.Printf("  Cipher Suites: %v", hello.CipherSuites)
            log.Printf("  Supported Curves: %v", hello.SupportedCurves)
            log.Printf("  Supported Points: %v", hello.SupportedPoints)

            return nil, nil  // Use default config
        }
    }

    return config
}