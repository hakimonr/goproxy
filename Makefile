.PHONY: build run test clean

# Build with optimizations
build:
	@echo "Building proxytool..."
	go build -ldflags="-s -w" -o proxytool main.go
	@echo "✓ Build complete"

# Run with GODEBUG
run: build
	@echo "Starting proxy with legacy TLS support..."
	GODEBUG=tls10default=1,tlsrsakex=1,tls3des=1,x509sha1=1 \
	./proxytool \
	-cert burp-ca-cert.pem \
	-key burp-ca-key.pem \
	-listen 0.0.0.0:8888 \
	-max-concurrent 1 \
	-delay 5000 \
	-log-level info

# Run in debug mode
debug: build
	@echo "Starting proxy in DEBUG mode..."
	GODEBUG=tls10default=1,tlsrsakex=1,tls3des=1,x509sha1=1 \
	./proxytool \
	-cert burp-ca-cert.pem \
	-key burp-ca-key.pem \
	-listen 0.0.0.0:8888 \
	-max-concurrent 1 \
	-delay 5000 \
	-log-level debug

# Test TLS compatibility
test:
	@echo "Testing TLS 1.0..."
	@curl -v --tlsv1.0 --tls-max 1.0 -x http://localhost:8888 -k https://example.com || true
	@echo ""
	@echo "Testing TLS 1.1..."
	@curl -v --tlsv1.1 --tls-max 1.1 -x http://localhost:8888 -k https://example.com || true
	@echo ""
	@echo "Testing TLS 1.2..."
	@curl -v --tlsv1.2 --tls-max 1.2 -x http://localhost:8888 -k https://example.com || true

# Clean build artifacts
clean:
	rm -f proxytool
	rm -f log/*.txt
	@echo "✓ Cleaned"