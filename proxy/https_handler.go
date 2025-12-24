package proxy

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

func (p *ProxyServer) handleHTTPS(w http.ResponseWriter, r *http.Request) {
    // Apply rate limiting
    if p.shouldThrottle(r.Host) {
        p.applyRateLimit()
    }

    log.Printf("[CONNECT] %s", r.Host)

    // ===== STEP 1: HIJACK CONNECTION =====
    hijacker, ok := w.(http.Hijacker)
    if !ok {
        http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
        return
    }

    clientConn, _, err := hijacker.Hijack()
    if err != nil {
        log.Printf("[ERROR] Hijack failed: %v", err)
        return
    }
    defer clientConn.Close()

    // ===== STEP 2: SEND 200 CONNECTION ESTABLISHED =====
    _, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
    if err != nil {
        log.Printf("[ERROR] Failed to write 200 response: %v", err)
        return
    }

    // ===== STEP 3: PEEK TO DETECT PROTOCOL =====
    // Use a small buffer to peek without using bufio.Reader to avoid buffering issues.
    // We read directly from the connection so we don't hide data in a bufio buffer.
    peekBuf := make([]byte, 5)

    // Set a timeout for peeking
    clientConn.SetReadDeadline(time.Now().Add(10 * time.Second))
    n, err := clientConn.Read(peekBuf)
    clientConn.SetReadDeadline(time.Time{}) // Reset deadline

    if err != nil && err != io.EOF {
        log.Printf("[ERROR] Failed to peek: %v", err)
        return
    }

    if n == 0 {
        return
    }

    firstBytes := peekBuf[:n]

    // Create the LimitedConn immediately so we can use it for all paths
    peekedConn := &LimitedConn{
        Conn:    clientConn,
        initial: firstBytes,
    }

    // ===== STEP 4: DETERMINE PROTOCOL =====
    isTLS := false
    isHTTP := false

    if len(firstBytes) > 0 {
        if firstBytes[0] == 0x16 {
            isTLS = true
        } else if isHTTPRequest(firstBytes) {
            isHTTP = true
        }
    }

    // ===== STEP 5: HANDLE BASED ON PROTOCOL =====
    if isHTTP {
        // Plain HTTP through CONNECT tunnel
        // Wrap peekedConn in bufio.Reader so it reads the initial bytes first
        p.handlePlainHTTPTunnel(clientConn, bufio.NewReader(peekedConn), r.Host)
        return
    }

    if !isTLS {
        // Not TLS, not HTTP - just pass through
        p.handleRawTunnel(clientConn, bufio.NewReader(peekedConn), r.Host)
        return
    }

    // ===== STEP 6: TLS MITM =====
    // Clone the TLS config to avoid modifying the original config
    tlsConfig := p.TLSConfig.Clone()

    tlsClientConn := tls.Server(peekedConn, tlsConfig)

    // Set handshake timeout (use configured value)
    tlsClientConn.SetDeadline(time.Now().Add(p.TLSTimeout))

    err = tlsClientConn.Handshake()
    if err != nil {
        log.Printf("[ERROR] TLS handshake failed: %v", err)
        tlsClientConn.Close()
        return
    }

    // Set idle timeout after successful handshake
    tlsClientConn.SetDeadline(time.Now().Add(p.IdleTimeout))

    // Log successful handshake details
    state := tlsClientConn.ConnectionState()
    log.Printf("[TLS] Handshake OK: %s | Version: %s | Cipher: %s",
        r.Host,
        tlsVersionToString(state.Version),
        tls.CipherSuiteName(state.CipherSuite),
    )

    // ===== STEP 7: CHECK CIRCUIT BREAKER AND HEALTH =====
    if p.CircuitBreaker != nil && p.CircuitBreaker.IsOpen(r.Host) {
        log.Printf("[CIRCUIT] Circuit open for %s, rejecting request", r.Host)
        tlsClientConn.Close()
        return
    }
    
    // Register host for health checking
    if p.HealthChecker != nil {
        p.HealthChecker.RegisterHost(r.Host)
        if !p.HealthChecker.IsHealthy(r.Host) {
            log.Printf("[HEALTH] Host %s is unhealthy, rejecting request", r.Host)
            tlsClientConn.Close()
            return
        }
    }

    // ===== STEP 8: CONNECT TO TARGET WITH RETRY =====
    targetAddr := r.Host
    if !hasPort(targetAddr) {
        targetAddr += ":443"
    }

    var targetConn net.Conn
    var targetIsTLS bool
    var connErr error
    
    // Retry logic for target connection
    for attempt := 0; attempt <= p.MaxRetries; attempt++ {
        if attempt > 0 {
            retryDelay := time.Duration(p.RetryDelayMs) * time.Millisecond
            log.Printf("[RETRY] Attempt %d/%d for %s after %v", attempt+1, p.MaxRetries+1, r.Host, retryDelay)
            time.Sleep(retryDelay)
        }
        
        targetConn, targetIsTLS, connErr = p.connectToTarget(targetAddr, r.Host)
        if connErr == nil {
            break
        }
        
        if attempt == p.MaxRetries {
            log.Printf("[ERROR] Target connection failed after %d attempts: %v", p.MaxRetries+1, connErr)
            if p.CircuitBreaker != nil {
                p.CircuitBreaker.RecordFailure(r.Host)
            }
            tlsClientConn.Close()
            return
        }
    }

    if p.CircuitBreaker != nil {
        p.CircuitBreaker.RecordSuccess(r.Host)
    }

    log.Printf("[TUNNEL] Established: Client <-> Proxy <-> %s (Target TLS: %v)", r.Host, targetIsTLS)

    // ===== STEP 9: HTTP-AWARE PROXY WITH GRACEFUL DEGRADATION =====
    proxyErr := p.proxyHTTPOverTLS(tlsClientConn, targetConn, r.Host)
    if proxyErr != nil {
        log.Printf("[WARN] HTTP proxy failed, falling back to tunnel mode: %v", proxyErr)
        p.fallbackToTunnel(tlsClientConn, targetConn, r.Host)
    }
}

// 🔥 NEW: Smart target connection with protocol detection
func (p *ProxyServer) connectToTarget(targetAddr, host string) (net.Conn, bool, error) {
    hostname := extractHostname(host)

    dialer := &net.Dialer{
        Timeout: p.ConnectTimeout,
    }

    rawConn, err := dialer.Dial("tcp", targetAddr)
    if err != nil {
        return nil, false, fmt.Errorf("TCP connection failed: %v", err)
    }

    tlsConfig := &tls.Config{
        InsecureSkipVerify: true,
        ServerName:         hostname,
        MinVersion:         tls.VersionTLS10,
        MaxVersion:         tls.VersionTLS13,
        Renegotiation:      tls.RenegotiateFreelyAsClient,
    }

    tlsConn := tls.Client(rawConn, tlsConfig)
    tlsConn.SetDeadline(time.Now().Add(p.TLSTimeout))
    err = tlsConn.Handshake()
    if err != nil {
        tlsConn.Close()
        return nil, false, err
    }

    tlsConn.SetDeadline(time.Now().Add(p.IdleTimeout))
    return tlsConn, true, nil
}

// Handle plain HTTP over CONNECT tunnel
func (p *ProxyServer) handlePlainHTTPTunnel(clientConn net.Conn, reader *bufio.Reader, host string) {
    targetAddr := host
    if !hasPort(targetAddr) {
        targetAddr += ":80"
    }

    targetConn, err := net.Dial("tcp", targetAddr)
    if err != nil {
        log.Printf("[ERROR] Target connection failed: %v", err)
        return
    }

    log.Printf("[TUNNEL] Plain HTTP: Client <-> Proxy <-> %s", host)

    var wg sync.WaitGroup
    var closeOnce sync.Once
    
    cleanup := func() {
        targetConn.Close()
        clientConn.Close()
    }

    wg.Add(2)

    go func() {
        defer wg.Done()
        _, err := io.Copy(targetConn, reader)
        closeOnce.Do(cleanup)
        if err != nil && !isExpectedError(err) {
            log.Printf("[ERROR] Tunnel client->target error: %v", err)
        }
    }()

    go func() {
        defer wg.Done()
        _, err := io.Copy(clientConn, targetConn)
        closeOnce.Do(cleanup)
        if err != nil && !isExpectedError(err) {
            log.Printf("[ERROR] Tunnel target->client error: %v", err)
        }
    }()

    wg.Wait()
}

// Handle raw TCP tunnel (no MITM)
func (p *ProxyServer) handleRawTunnel(clientConn net.Conn, reader *bufio.Reader, host string) {
    targetAddr := host
    if !hasPort(targetAddr) {
        targetAddr += ":443"
    }

    targetConn, err := net.Dial("tcp", targetAddr)
    if err != nil {
        log.Printf("[ERROR] Target connection failed: %v", err)
        return
    }

    log.Printf("[TUNNEL] Raw TCP: Client <-> Proxy <-> %s", host)

    var wg sync.WaitGroup
    var closeOnce sync.Once
    
    cleanup := func() {
        targetConn.Close()
        clientConn.Close()
    }

    wg.Add(2)

    go func() {
        defer wg.Done()
        _, err := io.Copy(targetConn, reader)
        closeOnce.Do(cleanup)
        if err != nil && !isExpectedError(err) {
            log.Printf("[ERROR] Tunnel client->target error: %v", err)
        }
    }()

    go func() {
        defer wg.Done()
        _, err := io.Copy(clientConn, targetConn)
        closeOnce.Do(cleanup)
        if err != nil && !isExpectedError(err) {
            log.Printf("[ERROR] Tunnel target->client error: %v", err)
        }
    }()

    wg.Wait()
}

// isExpectedError filters out expected errors that shouldn't be logged
func isExpectedError(err error) bool {
    if err == nil || err == io.EOF {
        return true
    }
    errStr := err.Error()
    return strings.Contains(errStr, "use of closed network connection") ||
           strings.Contains(errStr, "connection reset by peer") ||
           strings.Contains(errStr, "broken pipe")
}

// Helper: Check if bytes look like HTTP request
func isHTTPRequest(data []byte) bool {
    if len(data) < 3 {
        return false
    }

    // Check for common HTTP methods
    httpMethods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT"}
    for _, method := range httpMethods {
        if len(data) >= len(method) && string(data[:len(method)]) == method {
            return true
        }
    }

    return false
}

// Helper functions
func tlsVersionToString(version uint16) string {
    switch version {
    case tls.VersionSSL30:
        return "SSL 3.0"
    case tls.VersionTLS10:
        return "TLS 1.0"
    case tls.VersionTLS11:
        return "TLS 1.1"
    case tls.VersionTLS12:
        return "TLS 1.2"
    case tls.VersionTLS13:
        return "TLS 1.3"
    default:
        return fmt.Sprintf("Unknown (0x%x)", version)
    }
}

func hasPort(host string) bool {
    for i := len(host) - 1; i >= 0; i-- {
        if host[i] == ':' {
            return true
        }
        if host[i] == ']' {  // IPv6
            return false
        }
    }
    return false
}

func extractHostname(hostPort string) string {
    host, _, err := net.SplitHostPort(hostPort)
    if err != nil {
        return hostPort
    }
    return host
}

// proxyHTTPOverTLS intercepts and proxies HTTP requests/responses over TLS
func (p *ProxyServer) proxyHTTPOverTLS(clientConn, targetConn net.Conn, host string) error {
    defer clientConn.Close()
    defer targetConn.Close()

    clientReader := bufio.NewReader(clientConn)
    targetReader := bufio.NewReader(targetConn)

    for {
        // Read HTTP request from client
        startTime := time.Now()
        
        // Set request timeout
        clientConn.SetReadDeadline(time.Now().Add(p.RequestTimeout))
        req, err := http.ReadRequest(clientReader)
        clientConn.SetReadDeadline(time.Now().Add(p.IdleTimeout))
        
        if err != nil {
            if err != io.EOF && !isExpectedError(err) {
                return fmt.Errorf("failed to read request: %w", err)
            }
            return nil
        }

        // Log request to console
        log.Printf("[→] %s %s (%s)", req.Method, req.URL.Path, host)

        // Log request body if enabled
        if p.LogRequestBody && req.Body != nil {
            bodyBytes, err := io.ReadAll(io.LimitReader(req.Body, p.MaxLogBodySize))
            if err == nil && len(bodyBytes) > 0 {
                log.Printf("[REQ BODY] %s", string(bodyBytes))
                // Reconstruct body for forwarding
                req.Body = io.NopCloser(io.MultiReader(
                    strings.NewReader(string(bodyBytes)),
                    req.Body,
                ))
            }
        }

        // Forward request to target
        if err := req.Write(targetConn); err != nil {
            return fmt.Errorf("failed to forward request: %w", err)
        }

        // Read response from target
        resp, err := http.ReadResponse(targetReader, req)
        if err != nil {
            return fmt.Errorf("failed to read response: %w", err)
        }

        // Apply memory limit to response body
        if p.MaxResponseSize > 0 && resp.Body != nil {
            resp.Body = io.NopCloser(io.LimitReader(resp.Body, p.MaxResponseSize))
        }

        // Calculate timing
        duration := time.Since(startTime)

        // Log response to console
        log.Printf("[←] %d %s (%dms)", resp.StatusCode, http.StatusText(resp.StatusCode), duration.Milliseconds())

        // Adjust delay based on response (rate limit detection)
        if p.AdaptiveThrottler != nil {
            retryAfter := resp.Header.Get("Retry-After")
            p.AdaptiveThrottler.AdjustDelay(resp.StatusCode, duration, retryAfter, p.StrictThrottle)
        }

        // Handle compression
        contentEncoding := resp.Header.Get("Content-Encoding")
        if contentEncoding != "" && resp.Body != nil {
            var decompressedBody io.ReadCloser
            var decompErr error
            
            switch strings.ToLower(contentEncoding) {
            case "gzip":
                decompressedBody, decompErr = gzip.NewReader(resp.Body)
                if decompErr == nil {
                    log.Printf("[COMPRESSION] Decompressing gzip response")
                    resp.Body = decompressedBody
                    resp.Header.Del("Content-Encoding")
                    resp.ContentLength = -1 // Unknown after decompression
                }
            case "deflate":
                decompressedBody = flate.NewReader(resp.Body)
                log.Printf("[COMPRESSION] Decompressing deflate response")
                resp.Body = decompressedBody
                resp.Header.Del("Content-Encoding")
                resp.ContentLength = -1
            }
        }

        // Record advanced statistics
        if p.AdvancedStats != nil {
            bytesSent := req.ContentLength
            if bytesSent < 0 {
                bytesSent = 0
            }
            bytesReceived := resp.ContentLength
            if bytesReceived < 0 {
                bytesReceived = 0
            }
            p.AdvancedStats.RecordRequest(req.URL.Path, resp.StatusCode, duration, bytesSent, bytesReceived)
        }

        // Log response body if enabled
        if p.LogResponseBody && resp.Body != nil {
            bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, p.MaxLogBodySize))
            if err == nil && len(bodyBytes) > 0 {
                log.Printf("[RESP BODY] %s", string(bodyBytes))
                // Reconstruct body for forwarding
                resp.Body = io.NopCloser(io.MultiReader(
                    strings.NewReader(string(bodyBytes)),
                    resp.Body,
                ))
            }
        }

        // Forward response to client
        if err := resp.Write(clientConn); err != nil {
            resp.Body.Close()
            if !isExpectedError(err) {
                return fmt.Errorf("failed to forward response: %w", err)
            }
            return nil
        }
        resp.Body.Close()

        // Check if connection should be kept alive
        if !shouldKeepAlive(req, resp) {
            return nil
        }
    }
}

// shouldKeepAlive determines if the connection should be kept alive
func shouldKeepAlive(req *http.Request, resp *http.Response) bool {
    // HTTP/1.0 defaults to close unless explicitly kept alive
    if req.ProtoMajor == 1 && req.ProtoMinor == 0 {
        return strings.EqualFold(req.Header.Get("Connection"), "keep-alive")
    }
    // HTTP/1.1 defaults to keep-alive unless explicitly closed
    if strings.EqualFold(req.Header.Get("Connection"), "close") {
        return false
    }
    if strings.EqualFold(resp.Header.Get("Connection"), "close") {
        return false
    }
    return true
}

// fallbackToTunnel falls back to blind tunneling when HTTP parsing fails
func (p *ProxyServer) fallbackToTunnel(clientConn, targetConn net.Conn, host string) {
    log.Printf("[FALLBACK] Using blind tunnel mode for %s", host)
    
    var wg sync.WaitGroup
    var closeOnce sync.Once
    
    cleanup := func() {
        targetConn.Close()
        clientConn.Close()
    }

    wg.Add(2)

    go func() {
        defer wg.Done()
        _, err := io.Copy(targetConn, clientConn)
        closeOnce.Do(cleanup)
        if err != nil && !isExpectedError(err) {
            log.Printf("[ERROR] Fallback tunnel client->target error: %v", err)
        }
    }()

    go func() {
        defer wg.Done()
        _, err := io.Copy(clientConn, targetConn)
        closeOnce.Do(cleanup)
        if err != nil && !isExpectedError(err) {
            log.Printf("[ERROR] Fallback tunnel target->client error: %v", err)
        }
    }()

    wg.Wait()
}

// LimitedConn is a net.Conn wrapper that provides initial data before reading from the underlying connection
type LimitedConn struct {
    net.Conn
    initial []byte
    offset  int
}

func (c *LimitedConn) Read(p []byte) (n int, err error) {
    // If we have initial data to provide, provide it first
    if c.offset < len(c.initial) {
        n = copy(p, c.initial[c.offset:])
        c.offset += n
        return n, nil
    }
    // If initial data is exhausted, read from the underlying connection
    return c.Conn.Read(p)
}