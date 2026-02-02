.PHONY: build run generate-keys test clean help

# Build the license server
build:
	@echo "Building license server..."
	@go build -o license-server .
	@echo "✓ Built: ./license-server"

# Run the license server
run: build
	@echo "Starting license server on :8080"
	@./license-server --port 8080 --key keys/private.key --db licenses.db

# Generate a fresh Ed25519 keypair
generate-keys:
	@echo "Generating Ed25519 keypair..."
	@mkdir -p keys
	@go run tools/keygen.go
	@echo ""
	@echo "✓ Keys generated in keys/"
	@echo ""
	@echo "⚠️  IMPORTANT: Update pkg/license/license.go with the new public key!"
	@echo "   Public key is in keys/public.key"
	@echo ""
	@echo "   Replace the publicKeyB64 constant with the content of keys/public.key"

# Test the server (requires it to be running)
test:
	@echo "Testing health endpoint..."
	@curl -s http://localhost:8080/health | jq .
	@echo ""
	@echo "Testing license validation..."
	@curl -s http://localhost:8080/license/validate/test-key | jq .

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -f license-server licenses.db
	@echo "✓ Cleaned"

# Show help
help:
	@echo "TITO License Server - Makefile"
	@echo ""
	@echo "Commands:"
	@echo "  make build          - Build the license server binary"
	@echo "  make run            - Build and run the server on :8080"
	@echo "  make generate-keys  - Generate a fresh Ed25519 keypair"
	@echo "  make test           - Test the server (must be running)"
	@echo "  make clean          - Remove build artifacts and database"
	@echo "  make help           - Show this help"
	@echo ""
	@echo "Usage:"
	@echo "  1. make generate-keys     # Generate keypair once"
	@echo "  2. Update publicKeyB64 in ../pkg/license/license.go"
	@echo "  3. make run               # Start the server"
	@echo ""
	@echo "Environment variables:"
	@echo "  SMTP_HOST          - SMTP server hostname"
	@echo "  SMTP_PORT          - SMTP server port (e.g., 587)"
	@echo "  SMTP_USER          - SMTP username"
	@echo "  SMTP_PASSWORD      - SMTP password"
	@echo "  SMTP_FROM          - From email address"
	@echo "  LICENSE_API_KEY    - API key for /license/list endpoint"
