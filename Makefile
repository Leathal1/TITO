# TITO - Threat In, Threat Out
# Build automation for cross-platform distribution

BINARY_NAME=atip
VERSION=2.1.0
BUILD_DIR=dist
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: all build test clean install cross-compile

all: clean test build

build:
	@echo "🔨 Building $(BINARY_NAME)..."
	go build $(LDFLAGS) -o $(BINARY_NAME) ./cmd/atip
	@echo "✓ Built $(BINARY_NAME)"

test:
	@echo "🧪 Running tests..."
	go test -v ./...
	@echo "✓ All tests passed"

vet:
	@echo "🔍 Running vet..."
	go vet ./...
	@echo "✓ No issues"

coverage:
	@echo "📊 Running coverage..."
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "✓ Coverage report: coverage.html"

clean:
	@echo "🧹 Cleaning..."
	rm -rf $(BUILD_DIR) $(BINARY_NAME) coverage.out coverage.html
	@echo "✓ Clean"

install:
	@echo "📦 Installing $(BINARY_NAME)..."
	go install $(LDFLAGS) ./cmd/atip
	@echo "✓ Installed"

# Cross-compile for all platforms
cross-compile: clean
	@echo "🌍 Cross-compiling $(BINARY_NAME) v$(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	
	@echo "  → macOS (arm64)..."
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/atip
	
	@echo "  → macOS (amd64)..."
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/atip
	
	@echo "  → Linux (amd64)..."
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/atip
	
	@echo "  → Linux (arm64)..."
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/atip
	
	@echo "  → Windows (amd64)..."
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/atip
	
	@echo "✓ All binaries in $(BUILD_DIR)/"
	@ls -lh $(BUILD_DIR)/

# Package releases with checksums
release: cross-compile
	@echo "📋 Generating checksums..."
	cd $(BUILD_DIR) && shasum -a 256 * > checksums.txt
	@echo "✓ Release ready in $(BUILD_DIR)/"
	@cat $(BUILD_DIR)/checksums.txt

# Demo scan
demo:
	@echo "🎯 Running demo scan..."
	go run ./cmd/atip scan --repo https://github.com/OWASP/NodeGoat --maestro --semgrep --mitre --dataflow
	@echo "✓ Demo complete"

fmt:
	go fmt ./...

lint: vet
	@echo "✓ Lint passed"
