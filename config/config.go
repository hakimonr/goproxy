package config

import (
	"flag"
	"log"
)

type Config struct {
	ListenAddr           string
	CertPath             string
	KeyPath              string
	MaxConcurrent        int
	DelayMs              int
	TargetScope          string
	LogLevel             string
	LogFile              string
	AutoLogTimestamp     bool
	MaxLogSizeMB         int64
	UpstreamProxy        string
	DisableSSLVerify     bool
	ThrottleMode         string
	StrictThrottle       bool
	LogRequestBody       bool
	LogResponseBody      bool
	LogRequestHeaders    bool
	LogResponseHeaders   bool
	ExcludeContentTypes  string
	ExcludeExtensions    string
	MaxLogBodySize       int64
	StructuredLogging    bool
	// Retry logic
	MaxRetries           int
	RetryDelayMs         int
	// Circuit breaker
	CircuitBreakerThreshold int
	CircuitBreakerTimeout   int  // seconds
	// Timeout management
	ConnectTimeoutSec    int
	TLSTimeoutSec        int
	RequestTimeoutSec    int
	IdleTimeoutSec       int
	// Memory limits
	MaxResponseSizeMB    int64
	// Health checks
	HealthCheckInterval  int  // seconds, 0 = disabled
}

func ParseArgs() *Config {
	cfg := &Config{}

	flag.StringVar(&cfg.ListenAddr, "listen", "0.0.0.0:8888", "Proxy listen address")
	flag.StringVar(&cfg.CertPath, "cert", "", "Path to TLS certificate (PEM)")
	flag.StringVar(&cfg.KeyPath, "key", "", "Path to TLS private key (PEM)")
	flag.IntVar(&cfg.MaxConcurrent, "max-concurrent", 0, "Max concurrent requests (0 for no limit)")
	flag.IntVar(&cfg.DelayMs, "delay", 0, "Delay between requests in ms (0 for no delay)")
	flag.StringVar(&cfg.TargetScope, "target-scope", "", "Regex for target scope")
	flag.StringVar(&cfg.LogLevel, "log-level", "info", "Log level (debug|info|warn|error)")
	flag.StringVar(&cfg.LogFile, "log-file", "", "Log file path")
	flag.BoolVar(&cfg.AutoLogTimestamp, "auto-log-timestamp", true, "Auto-generate timestamped log files when log-file is not specified")
	flag.Int64Var(&cfg.MaxLogSizeMB, "max-log-size", 10, "Maximum log file size in MB before rotation (default 10MB)")
	flag.StringVar(&cfg.UpstreamProxy, "upstream", "", "Upstream proxy URL")
	flag.BoolVar(&cfg.DisableSSLVerify, "disable-ssl-verify", false, "Disable SSL verification")
	flag.StringVar(&cfg.ThrottleMode, "throttle-mode", "sequential", "Throttle mode")
	flag.BoolVar(&cfg.StrictThrottle, "strict-throttle", false, "Disable adaptive throttling, use exact delay always")
	flag.BoolVar(&cfg.LogRequestBody, "log-request-body", true, "Log request bodies (default true)")
	flag.BoolVar(&cfg.LogResponseBody, "log-response-body", true, "Log response bodies (default true)")
	flag.BoolVar(&cfg.LogRequestHeaders, "log-request-headers", true, "Log request headers (default true)")
	flag.BoolVar(&cfg.LogResponseHeaders, "log-response-headers", true, "Log response headers (default true)")
	flag.StringVar(&cfg.ExcludeContentTypes, "exclude-content-types", "image/*,application/pdf", "Comma-separated list of content types to exclude from logging")
	flag.StringVar(&cfg.ExcludeExtensions, "exclude-extensions", ".jpg,.jpeg,.png,.gif,.pdf,.css,.js,.ico,.svg", "Comma-separated list of file extensions to exclude from logging")
	flag.Int64Var(&cfg.MaxLogBodySize, "max-log-body-size", 10240, "Maximum size of request/response body to log in bytes (default 10KB)")
	flag.BoolVar(&cfg.StructuredLogging, "structured-logging", false, "Use structured logging format (JSON) (default false)")
	
	// Retry logic (default enabled)
	flag.IntVar(&cfg.MaxRetries, "max-retries", 3, "Maximum number of retries for failed requests (default 3)")
	flag.IntVar(&cfg.RetryDelayMs, "retry-delay", 1000, "Delay between retries in milliseconds (default 1000ms)")
	
	// Circuit breaker (default enabled)
	flag.IntVar(&cfg.CircuitBreakerThreshold, "circuit-breaker-threshold", 10, "Number of consecutive failures before opening circuit (default 10)")
	flag.IntVar(&cfg.CircuitBreakerTimeout, "circuit-breaker-timeout", 60, "Seconds to wait before closing circuit (default 60s)")
	
	// Timeout management
	flag.IntVar(&cfg.ConnectTimeoutSec, "connect-timeout", 15, "TCP connection timeout in seconds (default 15s)")
	flag.IntVar(&cfg.TLSTimeoutSec, "tls-timeout", 30, "TLS handshake timeout in seconds (default 30s)")
	flag.IntVar(&cfg.RequestTimeoutSec, "request-timeout", 60, "HTTP request timeout in seconds (default 60s)")
	flag.IntVar(&cfg.IdleTimeoutSec, "idle-timeout", 300, "Idle connection timeout in seconds (default 300s)")
	
	// Memory limits
	flag.Int64Var(&cfg.MaxResponseSizeMB, "max-response-size", 100, "Maximum response size in MB (default 100MB, 0 = unlimited)")
	
	// Health checks
	flag.IntVar(&cfg.HealthCheckInterval, "health-check-interval", 0, "Health check interval in seconds (default 0 - disabled)")

	flag.Parse()

	// Validate required parameters
	if cfg.CertPath == "" || cfg.KeyPath == "" {
		log.Fatal("[FATAL] Both --cert and --key must be provided")
	}

	return cfg
}