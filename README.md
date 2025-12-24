# GoProxy - Advanced HTTP/HTTPS Intercepting Proxy

A professional-grade intercepting proxy written in Go, designed for penetration testing and security scanning with advanced rate limiting, throttling, and robustness features that surpass traditional tools in automation scenarios.

## 🚀 Key Features

### Core Proxy Capabilities
- **HTTP/HTTPS MITM interception** with certificate generation
- **Real-time request/response logging** with body inspection
- **Burp Suite certificate integration** for seamless workflow
- **Upstream proxy chaining** for complex network setups
- **Target scope filtering** with regex patterns

### Advanced Rate Limiting & Throttling
- **Strict timing controls** - Bulletproof rate limiting bypass
- **Adaptive throttling** with 429 detection and Retry-After header support
- **Sequential processing** with configurable concurrency limits
- **Strict mode** (`--strict-throttle`) for exact timing enforcement
- **Perfect for bypassing "X requests per second" limits**

### Robustness & Reliability
- **Automatic retry logic** (configurable attempts with exponential backoff)
- **Circuit breaker protection** (auto-disable failing targets)
- **Advanced timeout management** (connect, TLS, request, idle timeouts)
- **Memory limits** with streaming for large responses
- **Compression support** (gzip/deflate auto-decompression)
- **Health checks** with background target monitoring
- **Advanced statistics** (per-endpoint metrics, bandwidth tracking)

### Automation & Integration
- **CLI-driven** - Perfect for scripting and CI/CD
- **Structured logging** with JSON output option
- **Auto-rotating log files** with size limits
- **Progress reporting** and performance metrics
- **Graceful degradation** (fallback to tunnel mode)

## 📦 Installation

```bash
# Prerequisites: Go 1.21+
git clone <repository>
cd goproxy
go mod tidy
go build -o goproxy .
```

## 🔧 Quick Start

### Basic Usage
```bash
./goproxy \
  --cert burp-ca-cert.pem \
  --key burp-ca-key.pem \
  --listen 0.0.0.0:8888
```

### Rate Limiting Bypass (Recommended)
```bash
./goproxy \
  --cert burp-ca-cert.pem \
  --key burp-ca-key.pem \
  --listen 0.0.0.0:8888 \
  --max-concurrent 1 \
  --delay 5000 \
  --strict-throttle
```

### Security Scanner Integration
```bash
./goproxy \
  --cert burp-ca-cert.pem \
  --key burp-ca-key.pem \
  --listen 127.0.0.1:8888 \
  --max-concurrent 1 \
  --delay 10000 \
  --strict-throttle \
  --target-scope ".*target\.com.*" \
  --log-file scanner.log
```

## 📖 How to Use the Tool

### Step 1: Prepare Certificates

**Option A: Use Burp Suite Certificates (Recommended)**
1. Open Burp Suite → Proxy → Options
2. Click "Import / export CA certificate"
3. Export "Certificate in DER format" → Save as `burp-ca-cert.der`
4. Export "Private key in DER format" → Save as `burp-ca-key.der`
5. Convert to PEM format:
```bash
openssl x509 -inform der -in burp-ca-cert.der -out burp-ca-cert.pem
openssl rsa -inform der -in burp-ca-key.der -out burp-ca-key.pem
```

**Option B: Generate Self-Signed Certificate**
```bash
openssl req -x509 -newkey rsa:4096 -keyout burp-ca-key.pem -out burp-ca-cert.pem -days 365 -nodes \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=ProxyCA"
```

### Step 2: Start the Proxy

**For Rate Limiting Bypass:**
```bash
./goproxy \
  --cert burp-ca-cert.pem \
  --key burp-ca-key.pem \
  --listen 0.0.0.0:8888 \
  --max-concurrent 1 \
  --delay 5000 \
  --strict-throttle \
  --log-level info
```

**For Security Scanner Integration:**
```bash
./goproxy \
  --cert burp-ca-cert.pem \
  --key burp-ca-key.pem \
  --listen 127.0.0.1:8888 \
  --max-concurrent 1 \
  --delay 10000 \
  --strict-throttle \
  --target-scope ".*example\.com.*" \
  --log-file scanner.log \
  --max-log-size 50
```

### Step 3: Configure Your Client/Scanner

**Manual Testing with curl:**
```bash
# HTTP requests
export http_proxy=http://127.0.0.1:8888
curl -v http://example.com

# HTTPS requests  
export https_proxy=http://127.0.0.1:8888
curl -v --cacert burp-ca-cert.pem https://example.com
```

**Browser Configuration:**
1. Open browser proxy settings
2. Set HTTP proxy: `127.0.0.1:8888`
3. Set HTTPS proxy: `127.0.0.1:8888`
4. Import `burp-ca-cert.pem` to browser's certificate store

**Security Scanner Configuration:**
1. **Acunetix/Invicti/Netsparker:**
   - Proxy settings: `127.0.0.1:8888`
   - Import CA certificate to scanner's trust store
   
2. **Custom Scripts:**
```python
import requests

proxies = {
    'http': 'http://127.0.0.1:8888',
    'https': 'http://127.0.0.1:8888'
}

response = requests.get('https://example.com', 
                       proxies=proxies, 
                       verify='burp-ca-cert.pem')
```

### Step 4: Monitor and Analyze

**Real-time Monitoring:**
- Watch console output for request/response logs
- Monitor throttling messages: `[THROTTLE] Sleeping for X.XXXs`
- Check progress reports every 2 minutes

**Log Analysis:**
```bash
# Follow live logs
tail -f scanner.log

# Search for specific patterns
grep "THROTTLE" scanner.log
grep "ERROR" scanner.log
grep "200 OK" scanner.log

# Count requests per endpoint
grep "→" scanner.log | awk '{print $4}' | sort | uniq -c | sort -nr
```

### Step 5: Advanced Usage Scenarios

**Scenario 1: Bypass "10 requests per second" limit**
```bash
./goproxy \
  --cert burp-ca-cert.pem \
  --key burp-ca-key.pem \
  --max-concurrent 1 \
  --delay 5000 \
  --strict-throttle
```

**Scenario 2: High-volume scanning with retries**
```bash
./goproxy \
  --cert burp-ca-cert.pem \
  --key burp-ca-key.pem \
  --max-concurrent 3 \
  --delay 2000 \
  --max-retries 5 \
  --circuit-breaker-threshold 20 \
  --health-check-interval 30
```

**Scenario 3: Stealth scanning with health checks**
```bash
./goproxy \
  --cert burp-ca-cert.pem \
  --key burp-ca-key.pem \
  --max-concurrent 1 \
  --delay 10000 \
  --strict-throttle \
  --health-check-interval 60 \
  --target-scope ".*target\.com.*" \
  --exclude-extensions ".jpg,.png,.css,.js,.ico"
```

### Step 6: Troubleshooting Common Issues

**Certificate Issues:**
```bash
# Verify certificate format
openssl x509 -in burp-ca-cert.pem -text -noout

# Check private key
openssl rsa -in burp-ca-key.pem -check
```

**Connection Issues:**
```bash
# Test proxy connectivity
curl -v --proxy http://127.0.0.1:8888 http://httpbin.org/ip

# Check if proxy is listening
netstat -tlnp | grep 8888
```

**Performance Tuning:**
```bash
# For faster scanning (less strict)
--delay 1000 --max-concurrent 5

# For maximum stealth (very strict)  
--delay 15000 --max-concurrent 1 --strict-throttle
```

## 🛠️ Configuration Options

### Essential Options
| Flag | Description | Default |
|------|-------------|---------|
| `--cert` | TLS certificate path (PEM) | **Required** |
| `--key` | TLS private key path (PEM) | **Required** |
| `--listen` | Proxy listen address | `0.0.0.0:8888` |

### Rate Limiting & Throttling
| Flag | Description | Default |
|------|-------------|---------|
| `--max-concurrent` | Max concurrent requests (0=unlimited) | `0` |
| `--delay` | Delay between requests (ms) | `0` |
| `--strict-throttle` | Disable adaptive throttling | `false` |
| `--throttle-mode` | Throttling mode (sequential/adaptive) | `sequential` |

### Robustness Features
| Flag | Description | Default |
|------|-------------|---------|
| `--max-retries` | Max retry attempts | `3` |
| `--retry-delay` | Delay between retries (ms) | `1000` |
| `--circuit-breaker-threshold` | Failures before circuit opens | `10` |
| `--circuit-breaker-timeout` | Circuit recovery timeout (s) | `60` |
| `--connect-timeout` | TCP connection timeout (s) | `15` |
| `--tls-timeout` | TLS handshake timeout (s) | `30` |
| `--request-timeout` | HTTP request timeout (s) | `60` |
| `--idle-timeout` | Idle connection timeout (s) | `300` |
| `--max-response-size` | Max response size (MB, 0=unlimited) | `100` |
| `--health-check-interval` | Health check interval (s, 0=disabled) | `0` |

### Logging & Output
| Flag | Description | Default |
|------|-------------|---------|
| `--log-level` | Log level (debug/info/warn/error) | `info` |
| `--log-file` | Log file path (auto-generated if empty) | `""` |
| `--structured-logging` | JSON log format | `false` |
| `--max-log-size` | Max log file size (MB) | `10` |
| `--log-request-body` | Log request bodies | `true` |
| `--log-response-body` | Log response bodies | `true` |
| `--max-log-body-size` | Max body size to log (bytes) | `10240` |

### Filtering & Scope
| Flag | Description | Default |
|------|-------------|---------|
| `--target-scope` | Target regex pattern | `""` |
| `--exclude-content-types` | Content types to exclude from logging | `image/*,application/pdf` |
| `--exclude-extensions` | File extensions to exclude | `.jpg,.png,.css,.js` |

## 🎯 Use Cases

### 1. Rate Limiting Bypass
Perfect for bypassing "10 requests per second" limits:
```bash
./goproxy --cert cert.pem --key key.pem --delay 5000 --strict-throttle --max-concurrent 1
```

### 2. Security Scanner Proxy
Integrate with Acunetix, Invicti, or custom scanners:
```bash
./goproxy --cert cert.pem --key key.pem --listen 127.0.0.1:8888 --target-scope ".*target\.com.*"
```

### 3. High-Volume Testing
Automated testing with retry logic and circuit breakers:
```bash
./goproxy --cert cert.pem --key key.pem --max-retries 5 --circuit-breaker-threshold 20
```

## 🔐 Certificate Setup

### Using Burp Suite Certificates
1. Export Burp CA certificate (DER format)
2. Convert to PEM:
```bash
openssl x509 -inform der -in burp-ca-cert.der -out burp-ca-cert.pem
openssl rsa -in burp-private-key.pem -out burp-ca-key.pem
```

### Generate Self-Signed Certificate
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

## 🧪 Testing

### HTTP Test
```bash
export http_proxy=http://localhost:8888
curl -v http://example.com
```

### HTTPS Test
```bash
export https_proxy=http://localhost:8888
curl -v --cacert cert.pem https://example.com
```

### Scanner Integration Test
```bash
# Configure your scanner to use proxy: 127.0.0.1:8888
# Trust the certificate in scanner's trust store
```

## 📊 Monitoring & Statistics

The proxy provides comprehensive monitoring:
- **Real-time progress reports** every 2 minutes
- **Advanced statistics** every 5 minutes (per-endpoint metrics)
- **Health status** for all targets
- **Bandwidth and timing analysis**
- **Error distribution tracking**

## ⚠️ Security & Legal

- **Authorized testing only** - Never use without explicit permission
- **Educational purposes** - For learning and authorized penetration testing
- **Certificate validation** - Ensure proper certificate handling in production
- **Target consent** - Always obtain written permission before testing

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| Certificate not trusted | Add CA cert to system trust store |
| Connection refused | Check proxy is running on correct port |
| Rate limiting detected | Increase `--delay` or enable `--strict-throttle` |
| Memory issues | Set `--max-response-size` limit |
| Slow performance | Adjust `--max-concurrent` and timeouts |

## 📝 License

This project is for educational and authorized penetration testing purposes only.
