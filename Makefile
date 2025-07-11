.PHONY: help build install install-secure secure run clean uninstall status test

# Configuration
BINARY_NAME=dnshield
VERSION=1.0.0

# Default target
.DEFAULT_GOAL := help

#=============================================================================
# Core Commands
#=============================================================================

help:
	@echo "DNShield - DNS filtering with HTTPS interception"
	@echo ""
	@echo "Quick Start (Choose ONE):"
	@echo "  make secure-mode-dns     DNS takeover with secure CA storage"
	@echo "  make secure-mode-ext     Network Extension mode (requires code signing)"
	@echo ""
	@echo "Commands:"
	@echo "  make build               Build the binary"
	@echo "  make install             Install with file-based CA storage"
	@echo "  make install-secure      Install with System Keychain storage"
	@echo "  make run                 Run DNShield (auto-detects mode)"
	@echo "  make run-auto            Run with automatic DNS configuration"
	@echo "  make status              Check DNShield status"
	@echo "  sudo make uninstall      Remove DNShield completely"
	@echo "  make clean               Remove build artifacts"
	@echo ""
	@echo "DNS Management:"
	@echo "  make configure-dns       Configure DNS on all interfaces"
	@echo "  make restore-dns         Restore previous DNS settings"
	@echo ""
	@echo "Debug Modes:"
	@echo "  make secure-mode-dns-debug    DNS mode with debug logging"
	@echo "  make secure-mode-ext-debug    Extension mode with debug logging"
	@echo ""
	@echo "Development:"
	@echo "  make test                Run tests"
	@echo "  make fmt                 Format code"
	@echo "  make dist                Create distribution package"

build:
	@echo "Building $(BINARY_NAME)..."
	@go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY_NAME) .
	@echo "Build complete: ./$(BINARY_NAME)"

# Build with Network Extension support (requires macOS and signing)
build-with-extension:
	@echo "Building $(BINARY_NAME) with Network Extension support..."
	@go build -tags extension -ldflags "-X main.version=$(VERSION)" -o $(BINARY_NAME) .
	@echo "Build complete with extension support: ./$(BINARY_NAME)"

# Simple installation (file-based CA storage)
install: clean build
	@echo ""
	@echo "Installing DNShield..."
	@echo ""
	@echo "Creating CA certificate..."
	@./$(BINARY_NAME) install-ca
	@echo ""
	@echo "Installing CA to System keychain (requires sudo)..."
	@echo "You will be prompted for your password."
	@sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.dnshield/ca.crt
	@echo ""
	@echo "✅ Installation complete!"
	@echo ""
	@echo "Next: make run"

# Secure installation (System Keychain storage)
install-secure: clean build
	@echo ""
	@echo "Installing DNShield (Secure Mode)..."
	@echo ""
	@echo "This mode stores the CA key in System Keychain for enhanced security."
	@echo "You will be prompted for sudo access."
	@echo ""
	@sudo DNSHIELD_SECURITY_MODE=v2 DNSHIELD_USE_KEYCHAIN=true ./$(BINARY_NAME) install-ca
	@echo ""
	@echo "Installing CA to System keychain..."
	@sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.dnshield/ca.crt
	@echo ""
	@echo "✅ Secure installation complete!"
	@echo ""
	@echo "Next: make run"

# DNS takeover mode with secure CA storage
secure-mode-dns: install-secure
	@echo ""
	@echo "Starting DNShield in secure DNS takeover mode..."
	@sudo DNSHIELD_SECURITY_MODE=v2 DNSHIELD_USE_KEYCHAIN=true ./$(BINARY_NAME) run --auto-configure-dns

# Network Extension mode (kernel-level filtering)
secure-mode-ext: build-with-extension
	@echo ""
	@echo "Building app bundle with Network Extension..."
	@./build-app-bundle.sh
	@echo ""
	@echo "Installing CA certificate (for block pages)..."
	@sudo DNSHIELD_SECURITY_MODE=v2 DNSHIELD_USE_KEYCHAIN=true DNShield.app/Contents/MacOS/$(BINARY_NAME) install-ca || true
	@sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.dnshield/ca.crt || true
	@echo ""
	@echo "Installing Network Extension..."
	@sudo DNShield.app/Contents/MacOS/$(BINARY_NAME) extension install || true
	@echo ""
	@echo "Starting DNShield in secure Network Extension mode..."
	@sudo DNSHIELD_SECURITY_MODE=v2 DNSHIELD_USE_KEYCHAIN=true DNShield.app/Contents/MacOS/$(BINARY_NAME) run --mode=extension

# DNS mode with debug logging
secure-mode-dns-debug: install-secure
	@echo ""
	@echo "Starting DNShield in secure DNS mode with DEBUG logging..."
	@sudo DNSHIELD_SECURITY_MODE=v2 DNSHIELD_USE_KEYCHAIN=true DNSHIELD_LOG_LEVEL=debug ./$(BINARY_NAME) run --auto-configure-dns

# Extension mode with debug logging
secure-mode-ext-debug: build-with-extension
	@echo ""
	@echo "Building app bundle with Network Extension..."
	@./build-app-bundle.sh
	@echo ""
	@echo "Installing CA certificate (for block pages)..."
	@sudo DNSHIELD_SECURITY_MODE=v2 DNSHIELD_USE_KEYCHAIN=true DNShield.app/Contents/MacOS/$(BINARY_NAME) install-ca || true
	@sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.dnshield/ca.crt || true
	@echo ""
	@echo "Installing Network Extension..."
	@sudo DNShield.app/Contents/MacOS/$(BINARY_NAME) extension install || true
	@echo ""
	@echo "Starting DNShield in secure Network Extension mode with DEBUG logging..."
	@sudo DNSHIELD_SECURITY_MODE=v2 DNSHIELD_USE_KEYCHAIN=true DNSHIELD_LOG_LEVEL=debug DNShield.app/Contents/MacOS/$(BINARY_NAME) run --mode=extension

# Run DNShield (auto-detects installation mode)
run: build
	@echo "Starting DNShield..."
	@echo "This requires sudo to bind to ports 53, 80, and 443."
	@if [ -f ~/.dnshield/ca.key ]; then \
		echo "Mode: Standard (file-based storage)"; \
		sudo ./$(BINARY_NAME) run; \
	elif [ -f ~/.dnshield/ca.crt ]; then \
		echo "Mode: Secure (Keychain storage)"; \
		sudo DNSHIELD_SECURITY_MODE=v2 DNSHIELD_USE_KEYCHAIN=true ./$(BINARY_NAME) run; \
	else \
		echo "❌ DNShield not installed. Run 'make install' first."; \
		exit 1; \
	fi

# Run with automatic DNS configuration
run-auto: build
	@echo "Starting DNShield with auto DNS configuration..."
	@echo "This will configure DNS on all interfaces and monitor for changes."
	@if [ -f ~/.dnshield/ca.key ]; then \
		sudo ./$(BINARY_NAME) run --auto-configure-dns; \
	elif [ -f ~/.dnshield/ca.crt ]; then \
		sudo DNSHIELD_SECURITY_MODE=v2 DNSHIELD_USE_KEYCHAIN=true ./$(BINARY_NAME) run --auto-configure-dns; \
	else \
		echo "❌ DNShield not installed. Run 'make install' first."; \
		exit 1; \
	fi

clean:
	@echo "Cleaning build artifacts..."
	@rm -f $(BINARY_NAME)
	@go clean

# Complete uninstall
uninstall:
	@if [ "$$(id -u)" != "0" ]; then \
		echo "❌ Uninstall requires administrator privileges"; \
		echo ""; \
		echo "Please run: sudo make uninstall"; \
		echo ""; \
		exit 1; \
	fi
	@echo "Uninstalling DNShield..."
	# Stop any running instances
	@pkill dnshield 2>/dev/null || true
	# Restore DNS settings if they were changed
	@if [ -f ./$(BINARY_NAME) ]; then \
		./$(BINARY_NAME) configure-dns --restore 2>/dev/null || true; \
	fi
	# Uninstall Network Extension if present
	@if [ -f ./$(BINARY_NAME) ]; then \
		./$(BINARY_NAME) extension uninstall 2>/dev/null || true; \
	fi
	# Run built-in uninstaller
	@if [ -f ./$(BINARY_NAME) ]; then \
		./$(BINARY_NAME) uninstall --all 2>/dev/null || true; \
	fi
	# Remove certificates from System keychain
	@if security find-certificate -c "DNShield" /Library/Keychains/System.keychain 2>/dev/null | grep -q "alis"; then \
		echo "Removing certificates from System keychain..."; \
		security find-certificate -c "DNShield" /Library/Keychains/System.keychain | grep "alis" | cut -d '"' -f 4 | while read cert; do \
			security delete-certificate -c "$$cert" /Library/Keychains/System.keychain 2>/dev/null || true; \
		done; \
	fi
	# Clean up remaining files and certificates
	@security delete-certificate -c "DNShield Root CA" ~/Library/Keychains/login.keychain-db 2>/dev/null || true
	@security delete-generic-password -s "com.dnshield.ca" 2>/dev/null || true
	@rm -rf ~/.dnshield
	@rm -f $(BINARY_NAME)
	@echo "✅ Uninstall complete"

#=============================================================================
# DNS Management
#=============================================================================

configure-dns: build
	@echo "Configuring DNS on all network interfaces..."
	@sudo ./$(BINARY_NAME) configure-dns

restore-dns: build
	@echo "Restoring DNS configuration..."
	@sudo ./$(BINARY_NAME) configure-dns --restore

#=============================================================================
# Utility Commands
#=============================================================================

status: build
	@./$(BINARY_NAME) status

update-rules: build
	@echo "Updating blocking rules from S3..."
	@sudo ./$(BINARY_NAME) update-rules

show-mode:
	@echo "Checking DNShield installation..."
	@if [ -f ~/.dnshield/ca.key ]; then \
		echo "Mode: Standard (file-based CA storage)"; \
		echo "CA certificate location: ~/.dnshield/ca.crt"; \
		echo "CA private key location: ~/.dnshield/ca.key"; \
	elif [ -f ~/.dnshield/ca.crt ]; then \
		echo "Mode: Secure (System Keychain storage)"; \
		echo "CA certificate location: ~/.dnshield/ca.crt"; \
		echo "CA private key location: System Keychain (protected)"; \
	else \
		echo "Status: Not installed"; \
	fi

#=============================================================================
# Development
#=============================================================================

test:
	@echo "Running tests..."
	@go test -v ./...

fmt:
	@echo "Formatting code..."
	@go fmt ./...

deps:
	@echo "Downloading dependencies..."
	@go mod download
	@go mod tidy

# Show current configuration
show-config:
	@if [ -f config.yaml ]; then \
		echo "Current configuration:"; \
		cat config.yaml; \
	else \
		echo "No config.yaml found. Using defaults."; \
	fi

#=============================================================================
# Distribution
#=============================================================================

# Build universal binary
build-universal:
	@echo "Building universal binary..."
	@GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY_NAME)-amd64 .
	@GOOS=darwin GOARCH=arm64 go build -ldflags "-X main.version=$(VERSION)" -o $(BINARY_NAME)-arm64 .
	@lipo -create -output $(BINARY_NAME) $(BINARY_NAME)-amd64 $(BINARY_NAME)-arm64
	@rm -f $(BINARY_NAME)-amd64 $(BINARY_NAME)-arm64
	@codesign --force --deep --sign - $(BINARY_NAME)
	@echo "Universal binary created and signed"

# Create distribution package
dist: build-universal
	@echo "Creating distribution package..."
	@mkdir -p dist
	@cp $(BINARY_NAME) dist/
	@cp README.md dist/
	@cp LICENSE.md dist/
	@cp config.example.yaml dist/
	@cp -r docs dist/
	@echo "Creating installer script..."
	@echo '#!/bin/bash\necho "Installing DNShield..."\ncp dnshield /usr/local/bin/\necho "Installation complete. Run: dnshield install-ca"' > dist/install.sh
	@chmod +x dist/install.sh
	@echo "Creating DMG..."
	@hdiutil create -volname "DNShield $(VERSION)" -srcfolder dist -ov -format UDZO dnshield-$(VERSION).dmg
	@rm -rf dist
	@echo "Distribution package created: dnshield-$(VERSION).dmg"


#=============================================================================
# Demo Setup (for testing)
#=============================================================================

demo: install
	@echo ""
	@echo "========================================="
	@echo "DNShield Demo Setup Complete!"
	@echo "========================================="
	@echo ""
	@echo "1. Configure your DNS:"
	@echo "   make configure-dns"
	@echo ""
	@echo "2. Run DNShield:"
	@echo "   make run"
	@echo ""
	@echo "3. Test by visiting blocked domains:"
	@echo "   https://doubleclick.net"
	@echo "   https://googleadservices.com"