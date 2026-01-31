# TITO - Threat In, Threat Out
# Build automation for cross-platform distribution

BINARY_NAME=tito
VERSION=2.1.0
BUILD_DIR=dist
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: all build test clean install cross-compile

all: clean test build

build:
	@echo "🔨 Building $(BINARY_NAME)..."
	go build $(LDFLAGS) -o $(BINARY_NAME) ./cmd/tito
	@echo "✓ Built $(BINARY_NAME)"

build-free:
	@echo "🔨 Building $(BINARY_NAME) (Free Edition)..."
	@echo "   (Runtime license checks still active)"
	go build $(LDFLAGS) -o $(BINARY_NAME)-free ./cmd/tito
	@echo "✓ Built $(BINARY_NAME)-free"

build-pro:
	@echo "🔨 Building $(BINARY_NAME) (Pro Edition)..."
	go build $(LDFLAGS) -o $(BINARY_NAME)-pro ./cmd/tito
	@echo "✓ Built $(BINARY_NAME)-pro"
	@echo "   Note: Pro features still require valid license key"

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
	go install $(LDFLAGS) ./cmd/tito
	@echo "✓ Installed"

# Cross-compile for all platforms
cross-compile: clean
	@echo "🌍 Cross-compiling $(BINARY_NAME) v$(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	
	@echo "  → macOS (arm64)..."
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/tito
	
	@echo "  → macOS (amd64)..."
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/tito
	
	@echo "  → Linux (amd64)..."
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/tito
	
	@echo "  → Linux (arm64)..."
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/tito
	
	@echo "  → Windows (amd64)..."
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/tito
	
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
	go run ./cmd/tito scan --repo https://github.com/OWASP/NodeGoat --maestro --semgrep --mitre --dataflow
	@echo "✓ Demo complete"

fmt:
	go fmt ./...

lint: vet
	@echo "✓ Lint passed"
