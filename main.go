package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
	"goproxy/config"
	"goproxy/cert"
	"goproxy/proxy"
)

// LogRotationWriter wraps a file to check size and rotate when needed
type LogRotationWriter struct {
	file        *os.File
	maxSize     int64
	currentSize int64
	logFileBase string
	logFileExt  string
}

func NewLogRotationWriter(logFile string, maxSizeMB int64) (*LogRotationWriter, error) {
	// Create log directory if it doesn't exist
	logDir := filepath.Dir(logFile)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, err
	}

	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	// Get initial file size
	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}

	return &LogRotationWriter{
		file:        file,
		maxSize:     maxSizeMB * 1024 * 1024, // Convert MB to bytes
		currentSize: stat.Size(),
		logFileBase: logFile[:len(logFile)-len(filepath.Ext(logFile))],
		logFileExt:  filepath.Ext(logFile),
	}, nil
}

func (w *LogRotationWriter) Write(p []byte) (n int, err error) {
	// Check if adding this data would exceed the max size
	if w.currentSize+int64(len(p)) > w.maxSize {
		err := w.rotate()
		if err != nil {
			return 0, err
		}
	}

	n, err = w.file.Write(p)
	w.currentSize += int64(n)
	return n, err
}

func (w *LogRotationWriter) rotate() error {
	// Close current file
	w.file.Close()

	// Create a new filename with timestamp
	timestamp := time.Now().Format("20060102_150405")
	rotatedFileName := fmt.Sprintf("%s_%s%s", w.logFileBase, timestamp, w.logFileExt)
	
	// Rename the current log file to the rotated name
	if err := os.Rename(w.logFileBase+w.logFileExt, rotatedFileName); err != nil {
		return err
	}

	// Create a new log file
	file, err := os.OpenFile(w.logFileBase+w.logFileExt, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	w.file = file
	w.currentSize = 0

	return nil
}

func (w *LogRotationWriter) Close() error {
	return w.file.Close()
}

// ConsoleWriter multiplexes log output to both file and console
type ConsoleWriter struct {
	fileWriter   io.Writer
	consoleWriter io.Writer
}

func NewConsoleWriter(fileWriter, consoleWriter io.Writer) *ConsoleWriter {
	return &ConsoleWriter{
		fileWriter:   fileWriter,
		consoleWriter: consoleWriter,
	}
}

func (cw *ConsoleWriter) Write(p []byte) (n int, err error) {
	// Write to file always
	n, err = cw.fileWriter.Write(p)
	if err != nil {
		return n, err
	}

	// Write to console only for important messages
	logLine := string(p)
	// Only show important messages on console
	if cw.containsImportantMessage(logLine) {
		cw.consoleWriter.Write(p)
	}
	return n, nil
}

func (cw *ConsoleWriter) containsImportantMessage(logLine string) bool {
	// Show startup, shutdown, and errors on console
	importantMessages := []string{
		"[INFO] Starting proxy",
		"[INFO] Proxy shutdown",
		"[ERROR]",
		"[FATAL]",
		"Received signal",
		"[THROTTLE]",
		"[PROGRESS]",
		"[→]",  // Request logs
		"[←]",  // Response logs
	}

	for _, msg := range importantMessages {
		if strings.Contains(logLine, msg) {
			return true
		}
	}
	return false
}

func main() {
	// Parse CLI arguments
	cfg := config.ParseArgs()
	
	// Auto-generate log file if not specified and auto-timestamp is enabled
	if cfg.LogFile == "" && cfg.AutoLogTimestamp {
		// Create a timestamped log file name
		timestamp := time.Now().Format("2006-01-02_15-04-05")
		cfg.LogFile = filepath.Join("log", fmt.Sprintf("%s_logs.txt", timestamp))
	}
	
	// Setup file logging with rotation (only if MaxLogSizeMB > 0)
	var fileWriter io.Writer
	
	if cfg.MaxLogSizeMB > 0 {
		// Use rotation writer if size limit is set
		logWriter, err := NewLogRotationWriter(cfg.LogFile, cfg.MaxLogSizeMB)
		if err != nil {
			log.Fatal(err)
		}
		defer logWriter.Close()
		fileWriter = logWriter
	} else {
		// Create log directory if it doesn't exist
		logDir := filepath.Dir(cfg.LogFile)
		if err := os.MkdirAll(logDir, 0755); err != nil {
			log.Fatal(err)
		}
		
		// Use regular file if no size limit
		logFile, err := os.OpenFile(cfg.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}
		defer logFile.Close()
		fileWriter = logFile
	}
	
	// Create multiplexed writer to output to both file and console (for important messages)
	consoleWriter := NewConsoleWriter(fileWriter, os.Stdout)
	log.SetOutput(consoleWriter)

	// Load TLS certificate
	tlsConfig, err := cert.LoadBurpCertificate(cfg.CertPath, cfg.KeyPath)
	if err != nil {
		log.Fatalf("[FATAL] Failed to load certificate: %v", err)
	}
	
	// Compile target scope regex
	var scopeRegex *regexp.Regexp
	if cfg.TargetScope != "" {
		scopeRegex, err = regexp.Compile(cfg.TargetScope)
		if err != nil {
			log.Fatalf("[FATAL] Invalid target scope regex: %v", err)
		}
	}
	
	// Create circuit breaker if enabled
	var circuitBreaker *proxy.CircuitBreaker
	if cfg.CircuitBreakerThreshold > 0 {
		circuitBreaker = proxy.NewCircuitBreaker(
			cfg.CircuitBreakerThreshold,
			time.Duration(cfg.CircuitBreakerTimeout)*time.Second,
		)
	}
	
	// Create adaptive throttler
	adaptiveThrottler := proxy.NewAdaptiveThrottler(time.Duration(cfg.DelayMs) * time.Millisecond)
	
	// Create advanced stats
	advancedStats := proxy.NewAdvancedStats()
	
	// Create health checker
	var healthChecker *proxy.HealthChecker
	if cfg.HealthCheckInterval > 0 {
		healthChecker = proxy.NewHealthChecker(time.Duration(cfg.HealthCheckInterval) * time.Second)
	}
	
	// Create proxy server
	proxyServer := &proxy.ProxyServer{
		ListenAddr:         cfg.ListenAddr,
		MaxConcurrent:      cfg.MaxConcurrent,
		DelayMs:            cfg.DelayMs,
		TargetScope:        scopeRegex,
		TLSConfig:          tlsConfig,
		DisableSSLVerify:   cfg.DisableSSLVerify,
		UpstreamProxy:      cfg.UpstreamProxy,
		ThrottleMode:       cfg.ThrottleMode,
		StrictThrottle:     cfg.StrictThrottle,
		LogWriter:          fileWriter,
		LogRequestBody:     cfg.LogRequestBody,
		LogResponseBody:    cfg.LogResponseBody,
		LogRequestHeaders:  cfg.LogRequestHeaders,
		LogResponseHeaders: cfg.LogResponseHeaders,
		ExcludeContentTypes: strings.Split(cfg.ExcludeContentTypes, ","),
		ExcludeExtensions:   strings.Split(cfg.ExcludeExtensions, ","),
		MaxLogBodySize:      cfg.MaxLogBodySize,
		StructuredLogging:   cfg.StructuredLogging,
		MaxRetries:          cfg.MaxRetries,
		RetryDelayMs:        cfg.RetryDelayMs,
		CircuitBreaker:      circuitBreaker,
		ConnectTimeout:      time.Duration(cfg.ConnectTimeoutSec) * time.Second,
		TLSTimeout:          time.Duration(cfg.TLSTimeoutSec) * time.Second,
		RequestTimeout:      time.Duration(cfg.RequestTimeoutSec) * time.Second,
		IdleTimeout:         time.Duration(cfg.IdleTimeoutSec) * time.Second,
		AdaptiveThrottler:   adaptiveThrottler,
		AdvancedStats:       advancedStats,
		MaxResponseSize:     cfg.MaxResponseSizeMB * 1024 * 1024,
		HealthChecker:       healthChecker,
	}
	
	// Create a context that can be cancelled
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// Create a context that can be cancelled
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	
	// Start health checker if enabled
	if healthChecker != nil {
		go healthChecker.Start(ctx)
	}
	
	// Start proxy in a goroutine
	errChan := make(chan error, 1)
	go func() {
		log.Printf("[INFO] Starting proxy with config:")
		log.Printf("  Listen: %s", cfg.ListenAddr)
		log.Printf("  Max Concurrent: %d", cfg.MaxConcurrent)
		log.Printf("  Delay: %dms", cfg.DelayMs)
		log.Printf("  Target Scope: %s", cfg.TargetScope)
		log.Printf("  Throttle Mode: %s", cfg.ThrottleMode)
		log.Printf("  Strict Throttle: %v", cfg.StrictThrottle)
		log.Printf("  Log File: %s", cfg.LogFile) // Add log file info to startup message
		log.Printf("  Max Log Size: %d MB", cfg.MaxLogSizeMB)
		
		if err := proxyServer.Start(ctx); err != nil {
			log.Printf("[ERROR] Proxy server error: %v", err)
			errChan <- err
		}
	}()
	
	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	
	// Wait for either a signal or an error from the server
	select {
	case sig := <-sigChan:
		log.Printf("[INFO] Received signal: %v. Shutting down gracefully...", sig)
		cancel() // Cancel the context to stop the proxy
	case err := <-errChan:
		log.Printf("[ERROR] Proxy server error: %v", err)
		os.Exit(1)
	}
	
	log.Printf("[INFO] Proxy shutdown complete")
}