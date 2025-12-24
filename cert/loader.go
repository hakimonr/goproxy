package cert

import (
    "crypto/tls"
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "io/ioutil"
    "log"
    "sync"
)

var (
    certCache      = make(map[string]*tls.Certificate)
    certCacheMutex sync.RWMutex
)

func LoadBurpCertificate(caCertPath, caKeyPath string) (*tls.Config, error) {
    // Load CA certificate and key
    caCertPEM, err := ioutil.ReadFile(caCertPath)
    if err != nil {
        return nil, fmt.Errorf("failed to read CA cert: %v", err)
    }

    caKeyPEM, err := ioutil.ReadFile(caKeyPath)
    if err != nil {
        return nil, fmt.Errorf("failed to read CA key: %v", err)
    }

    // Parse CA certificate
    caCertBlock, _ := pem.Decode(caCertPEM)
    if caCertBlock == nil {
        return nil, fmt.Errorf("failed to parse CA certificate PEM")
    }

    caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
    if err != nil {
        return nil, fmt.Errorf("failed to parse CA certificate: %v", err)
    }

    // Parse CA private key
    caKeyBlock, _ := pem.Decode(caKeyPEM)
    if caKeyBlock == nil {
        return nil, fmt.Errorf("failed to parse CA key PEM")
    }

    var caKey interface{}
    caKey, err = x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
    if err != nil {
        // Try PKCS8 format
        caKey, err = x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
        if err != nil {
            return nil, fmt.Errorf("failed to parse CA key: %v", err)
        }
    }

    // 🔥 TLS Configuration based on mitmproxy best practices for maximum compatibility
    tlsConfig := &tls.Config{
        // Dynamic certificate generation using CA
        Certificates: nil,

        // Accept all TLS versions for maximum compatibility
        MinVersion:   tls.VersionTLS10,  // Start with TLS 1.0 for maximum compat
        MaxVersion:   tls.VersionTLS13,  // Support up to TLS 1.3

        // Support HTTP/2 and HTTP/1.1 via ALPN
        NextProtos: []string{"h2", "http/1.1"},

        // Use a comprehensive set of cipher suites to maximize compatibility
        // This includes modern and legacy cipher suites to support various clients
        CipherSuites: []uint16{
            // TLS 1.3 cipher suites
            tls.TLS_AES_128_GCM_SHA256,
            tls.TLS_AES_256_GCM_SHA384,
            tls.TLS_CHACHA20_POLY1305_SHA256,
            // TLS 1.2 cipher suites
            tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
            tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
            // Legacy cipher suites for older clients
            tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
            tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_RSA_WITH_AES_128_CBC_SHA,
            tls.TLS_RSA_WITH_AES_256_CBC_SHA,
        },

        // Don't prefer server cipher suites - let client choose (better compatibility)
        PreferServerCipherSuites: false,

        // Skip target verification (we're a proxy)
        InsecureSkipVerify: true,

        // Disable session tickets to avoid potential compatibility issues
        SessionTicketsDisabled: true,

        // Allow renegotiation
        Renegotiation: tls.RenegotiateFreelyAsClient,

        // Add support for various curve preferences
        CurvePreferences: []tls.CurveID{
            tls.X25519,
            tls.CurveP256,
            tls.CurveP384,
            tls.CurveP521,
        },

        // Dynamic certificate generation using CA with caching
        GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
            if hello.ServerName == "" {
                log.Printf("[WARN] No ServerName (SNI) provided!")
                hello.ServerName = "unknown.local"
            }

            // Check cache first
            certCacheMutex.RLock()
            if cert, ok := certCache[hello.ServerName]; ok {
                certCacheMutex.RUnlock()
                return cert, nil
            }
            certCacheMutex.RUnlock()

            log.Printf("[CERT] Generating certificate for: %s", hello.ServerName)

            // Generate a leaf certificate signed by the CA
            cert, err := GenerateCertForDomain(hello.ServerName, *caCert, caKey)
            if err != nil {
                log.Printf("[ERROR] Failed to generate certificate: %v", err)
                return nil, err
            }

            // Store in cache
            certCacheMutex.Lock()
            certCache[hello.ServerName] = cert
            certCacheMutex.Unlock()

            log.Printf("[INFO] Generated certificate for: %s", hello.ServerName)
            return cert, nil
        },
    }

    return tlsConfig, nil
}