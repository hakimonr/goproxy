package cert

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "fmt"
    "math/big"
    "net"
    "time"
)

func GenerateCertForDomain(domain string, caCert x509.Certificate, caKey interface{}) (*tls.Certificate, error) {
    // Generate new RSA key
    priv, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return nil, fmt.Errorf("failed to generate RSA key: %v", err)
    }

    // Serial number
    serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
    if err != nil {
        return nil, fmt.Errorf("failed to generate serial number: %v", err)
    }

    // Certificate template
    template := x509.Certificate{
        SerialNumber: serialNumber,
        Subject: pkix.Name{
            CommonName:   domain,
            Organization: []string{"Mitmproxy"},  // Match Burp's behavior
        },
        NotBefore:             time.Now().Add(-24 * time.Hour),  // Valid from yesterday
        NotAfter:              time.Now().Add(365 * 24 * time.Hour),  // Valid for 1 year

        // ===== KEY USAGES =====
        KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
        ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

        // ===== BASIC CONSTRAINTS =====
        BasicConstraintsValid: true,
        IsCA:                  false,
    }

    // Handle IP addresses vs Domain names
    if ip := net.ParseIP(domain); ip != nil {
        template.IPAddresses = []net.IP{ip}
    } else {
        template.DNSNames = []string{domain}
        
        // If domain is wildcard, add base domain too
        if len(domain) > 2 && domain[:2] == "*." {
            baseDomain := domain[2:]
            template.DNSNames = append(template.DNSNames, baseDomain)
        }
    }

    // Sign certificate with CA
    certBytes, err := x509.CreateCertificate(
        rand.Reader,
        &template,
        &caCert,               // Parent (CA cert)
        &priv.PublicKey,       // Public key of generated cert
        caKey,                 // Private key of CA (for signing)
    )
    if err != nil {
        return nil, fmt.Errorf("failed to create certificate: %v", err)
    }

    return &tls.Certificate{
        Certificate: [][]byte{certBytes, caCert.Raw},  // Include CA in chain
        PrivateKey:  priv,
    }, nil
}