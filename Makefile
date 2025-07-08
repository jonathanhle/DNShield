.PHONY: build run install-ca clean demo test

# Binary name
BINARY_NAME=dns-guardian
VERSION=1.0.0

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY_NAME) .
	@echo "Build complete: ./$(BINARY_NAME)"

# Run the agent (requires sudo)
run: build
	@echo "Starting DNS Guardian..."
	sudo ./$(BINARY_NAME) run

# Install CA certificate
install-ca: build
	@echo "Installing CA certificate..."
	./$(BINARY_NAME) install-ca

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -f $(BINARY_NAME)
	go clean

# Full demo setup
demo: clean build install-ca
	@echo ""
	@echo "========================================="
	@echo "DNS Guardian Demo Setup Complete!"
	@echo "========================================="
	@echo ""
	@echo "Next steps:"
	@echo "1. Set your DNS to 127.0.0.1:"
	@echo "   sudo networksetup -setdnsservers Wi-Fi 127.0.0.1"
	@echo ""
	@echo "2. Run the agent:"
	@echo "   make run"
	@echo ""
	@echo "3. Test by visiting:"
	@echo "   https://example-blocked.com"
	@echo "   https://doubleclick.net"
	@echo ""

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

# Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...

# Build for multiple platforms
build-all:
	@echo "Building for multiple platforms..."
	GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY_NAME)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY_NAME)-darwin-arm64 .
	@echo "Builds complete"

# Show current configuration
show-config:
	@echo "Current configuration:"
	@cat config.yaml

# Check agent status
status: build
	./$(BINARY_NAME) status

# Force update rules from S3
update-rules: build
	sudo ./$(BINARY_NAME) update-rules

# Code signing variables
CODESIGN_IDENTITY ?= "Developer ID Application"
ENTITLEMENTS = dns-guardian.entitlements

# Build and sign for production (requires Apple Developer ID)
build-signed: build
	@echo "Signing $(BINARY_NAME) for production..."
	codesign --force --options runtime --entitlements $(ENTITLEMENTS) --sign "$(CODESIGN_IDENTITY)" $(BINARY_NAME)
	@echo "Verifying signature..."
	codesign --verify --verbose $(BINARY_NAME)
	@echo "Binary signed successfully"

# Build with ad-hoc signature for local testing (no Apple ID required)
build-local-signed: build
	@echo "Signing $(BINARY_NAME) with ad-hoc signature for local testing..."
	@echo "Note: This signature is only valid on this machine"
	codesign --force --deep --sign - $(BINARY_NAME)
	@echo "Verifying local signature..."
	codesign --verify --verbose $(BINARY_NAME)
	@echo "Local signed binary ready for testing"

# Build universal binary for distribution
build-universal:
	@echo "Building universal binary..."
	GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY_NAME)-amd64 .
	GOOS=darwin GOARCH=arm64 go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY_NAME)-arm64 .
	lipo -create -output $(BINARY_NAME) $(BINARY_NAME)-amd64 $(BINARY_NAME)-arm64
	rm -f $(BINARY_NAME)-amd64 $(BINARY_NAME)-arm64
	@echo "Universal binary created"

# Build, sign, and notarize for distribution
dist: build-universal
	@echo "Signing universal binary..."
	codesign --force --options runtime --entitlements $(ENTITLEMENTS) --sign "$(CODESIGN_IDENTITY)" $(BINARY_NAME)
	@echo "Creating DMG..."
	mkdir -p dist
	cp $(BINARY_NAME) dist/
	cp README.md dist/
	cp -r docs dist/
	hdiutil create -volname "DNS Guardian" -srcfolder dist -ov -format UDZO dns-guardian-$(VERSION).dmg
	@echo "Signing DMG..."
	codesign --force --sign "$(CODESIGN_IDENTITY)" dns-guardian-$(VERSION).dmg
	@echo "Distribution DMG created: dns-guardian-$(VERSION).dmg"
	@echo ""
	@echo "Next steps for notarization:"
	@echo "1. xcrun notarytool submit dns-guardian-$(VERSION).dmg --apple-id YOUR_APPLE_ID --team-id YOUR_TEAM_ID --wait"
	@echo "2. xcrun stapler staple dns-guardian-$(VERSION).dmg"
	rm -rf dist

# Verify code signature
verify-signature:
	@echo "Verifying code signature..."
	codesign --verify --deep --verbose=2 $(BINARY_NAME)
	@echo "Checking entitlements..."
	codesign -d --entitlements - $(BINARY_NAME)

# Install signed binary
install-signed: build-signed install-ca
	@echo "Installing signed binary..."
	sudo cp $(BINARY_NAME) /usr/local/bin/
	@echo "Installation complete"

# Security mode for v2.0 (cryptocurrency exchange)
enable-v2-security:
	@echo "Enabling v2.0 security mode..."
	@echo "export DNS_GUARDIAN_SECURITY_MODE=v2" >> ~/.zshrc
	@echo "export DNS_GUARDIAN_USE_KEYCHAIN=true" >> ~/.zshrc
	@echo ""
	@echo "V2.0 security mode enabled. Please restart your terminal."
	@echo "Next: Run 'make install-ca' to install CA with Keychain storage"

# Test v2.0 security mode locally (no Apple ID required)
test-v2-local: build-local-signed
	@echo ""
	@echo "========================================="
	@echo "Testing DNS Guardian v2.0 Security Mode"
	@echo "========================================="
	@echo ""
	@echo "Installing CA with Keychain storage..."
	DNS_GUARDIAN_SECURITY_MODE=v2 DNS_GUARDIAN_USE_KEYCHAIN=true ./$(BINARY_NAME) install-ca
	@echo ""
	@echo "✅ Local v2.0 testing setup complete!"
	@echo ""
	@echo "Next steps:"
	@echo "1. Run with v2 mode: DNS_GUARDIAN_SECURITY_MODE=v2 sudo ./$(BINARY_NAME) run"
	@echo "2. Check audit logs: tail -f ~/.dns-guardian/audit/*.log"
	@echo "3. Test uninstall: ./$(BINARY_NAME) uninstall"
	@echo ""
	@echo "Note: You may see Keychain access prompts - click 'Always Allow'"

# Quick local v2 demo
demo-v2-local: clean test-v2-local
	@echo ""
	@echo "Starting DNS Guardian in v2.0 mode..."
	@echo "Press Ctrl+C to stop"
	@echo ""
	DNS_GUARDIAN_SECURITY_MODE=v2 sudo ./$(BINARY_NAME) run

# Complete cleanup - removes EVERYTHING
clean-all:
	@echo "🧹 Complete DNS Guardian cleanup..."
	@echo "Stopping any running instances..."
	@pkill dns-guardian 2>/dev/null || true
	@echo "Removing binary..."
	@rm -f $(BINARY_NAME)
	@echo "Removing all DNS Guardian data..."
	@rm -rf ~/.dns-guardian 2>/dev/null || sudo rm -rf ~/.dns-guardian
	@echo "Removing from System keychain..."
	@security find-certificate -a -c "DNS Guardian" /Library/Keychains/System.keychain | grep "alis" | cut -d '"' -f 4 | while read cert; do \
		echo "  Removing: $$cert"; \
		sudo security delete-certificate -c "$$cert" /Library/Keychains/System.keychain 2>/dev/null || true; \
	done
	@security find-certificate -a -c "DNS Guardian" /Library/Keychains/System.keychain | grep "alis" | cut -d '"' -f 4 | while read cert; do \
		echo "  Removing: $$cert"; \
		sudo security delete-certificate -c "$$cert" /Library/Keychains/System.keychain 2>/dev/null || true; \
	done
	@echo "Removing from login keychain..."
	@security delete-certificate -c "DNS Guardian Root CA" ~/Library/Keychains/login.keychain-db 2>/dev/null || true
	@echo "Removing Keychain passwords..."
	@security delete-generic-password -s "com.dnsguardian.ca" 2>/dev/null || true
	@echo "Cleaning Go cache..."
	@go clean -cache
	@echo "✅ Complete cleanup done!"

# Install and run v1 mode (file-based CA)
install-v1: clean-all build-local-signed
	@echo ""
	@echo "========================================="
	@echo "Installing DNS Guardian v1.0 (File-based)"
	@echo "========================================="
	@echo ""
	@echo "Creating CA..."
	@./$(BINARY_NAME) install-ca
	@echo ""
	@echo "Installing CA to System keychain..."
	@sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.dns-guardian/ca.crt
	@echo ""
	@echo "✅ v1.0 installation complete!"
	@echo ""
	@echo "Next: make run-v1"

# Install and run v2 mode (Keychain-based CA)  
install-v2: clean-all build-local-signed
	@echo ""
	@echo "========================================="
	@echo "Installing DNS Guardian v2.0 (Keychain)"
	@echo "========================================="
	@echo ""
	@echo "Creating CA with Keychain storage..."
	@DNS_GUARDIAN_SECURITY_MODE=v2 DNS_GUARDIAN_USE_KEYCHAIN=true ./$(BINARY_NAME) install-ca
	@echo ""
	@echo "Installing CA to System keychain..."
	@sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.dns-guardian/ca.crt
	@echo ""
	@echo "✅ v2.0 installation complete!"
	@echo ""
	@echo "Next: make run-v2"

# Run in v1 mode
run-v1: build
	@echo "Starting DNS Guardian v1.0 (file-based)..."
	@echo "Press Ctrl+C to stop"
	@sudo ./$(BINARY_NAME) run

# Run in v2 mode
run-v2: build
	@echo "Starting DNS Guardian v2.0 (Keychain)..."
	@echo "Press Ctrl+C to stop"
	@sudo DNS_GUARDIAN_SECURITY_MODE=v2 DNS_GUARDIAN_USE_KEYCHAIN=true ./$(BINARY_NAME) run

# Test v1 installation (non-interactive)
test-v1: install-v1
	@echo ""
	@echo "Testing v1.0 installation..."
	@echo "CA Algorithm:"
	@openssl x509 -in ~/.dns-guardian/ca.crt -text -noout | grep "Public Key Algorithm"
	@echo "CA Validity:"
	@openssl x509 -in ~/.dns-guardian/ca.crt -text -noout | grep -A2 "Validity"
	@echo "Files created:"
	@ls -la ~/.dns-guardian/
	@echo ""
	@echo "✅ v1.0 test complete. Run 'make run-v1' to start service."

# Test v2 installation (non-interactive)
test-v2: install-v2
	@echo ""
	@echo "Testing v2.0 installation..."
	@echo "CA Algorithm:"
	@openssl x509 -in ~/.dns-guardian/ca.crt -text -noout | grep "Public Key Algorithm"
	@echo "CA Validity:"
	@openssl x509 -in ~/.dns-guardian/ca.crt -text -noout | grep -A2 "Validity"
	@echo "Files created (should be NO ca.key):"
	@ls -la ~/.dns-guardian/
	@echo "Keychain entries:"
	@security find-generic-password -s "com.dnsguardian.ca" 2>/dev/null | grep "acct" || echo "Key stored in Keychain"
	@echo ""
	@echo "✅ v2.0 test complete. Run 'make run-v2' to start service."

# Quick switch between v1 and v2
switch-to-v1: clean-all install-v1
	@echo "Switched to v1.0 mode"

switch-to-v2: clean-all install-v2
	@echo "Switched to v2.0 mode"

# Show current mode
show-mode:
	@echo "Checking current DNS Guardian mode..."
	@if [ -f ~/.dns-guardian/ca.key ]; then \
		echo "Mode: v1.0 (file-based) - ca.key file exists"; \
	elif [ -f ~/.dns-guardian/ca.crt ]; then \
		echo "Mode: v2.0 (Keychain) - only ca.crt exists"; \
	else \
		echo "Not installed"; \
	fi
	@echo ""
	@echo "Certificates in System keychain:"
	@security find-certificate -c "DNS Guardian" /Library/Keychains/System.keychain 2>/dev/null | grep "labl" || echo "None found"