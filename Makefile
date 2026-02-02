# TITO - Threat In, Threat Out
# Build automation for cross-platform distribution

BINARY_NAME=tito
VERSION=2.1.0
BUILD_DIR=dist
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: all build test clean install cross-compile release \
        lint vet fmt coverage docker-build docker-push \
        sarif goreleaser-check demo self-scan

# ── Core ──

all: clean lint test build

build:
	@echo "🔨 Building $(BINARY_NAME)..."
	go build $(LDFLAGS) -o $(BINARY_NAME) ./cmd/tito
	@echo "✓ Built $(BINARY_NAME)"

test:
	@echo "🧪 Running tests..."
	go test -v -race ./...
	@echo "✓ All tests passed"

test-short:
	@echo "🧪 Running short tests..."
	go test -short ./...
	@echo "✓ Short tests passed"

clean:
	@echo "🧹 Cleaning..."
	rm -rf $(BUILD_DIR) $(BINARY_NAME) coverage.out coverage.html *.sarif
	@echo "✓ Clean"

install:
	@echo "📦 Installing $(BINARY_NAME)..."
	go install $(LDFLAGS) ./cmd/tito
	@echo "✓ Installed"

# ── Quality ──

lint:
	@echo "🔍 Running linter..."
	@if command -v golangci-lint &>/dev/null; then \
		golangci-lint run --timeout=5m; \
	else \
		echo "⚠️  golangci-lint not found, running go vet only"; \
		go vet ./...; \
	fi
	@echo "✓ Lint passed"

vet:
	@echo "🔍 Running vet..."
	go vet ./...
	@echo "✓ No issues"

fmt:
	@echo "📝 Formatting..."
	go fmt ./...
	@echo "✓ Formatted"

fmt-check:
	@echo "📝 Checking format..."
	@test -z "$$(gofmt -l .)" || { echo "❌ Unformatted files:"; gofmt -l .; exit 1; }
	@echo "✓ All formatted"

coverage:
	@echo "📊 Running coverage..."
	go test -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	@go tool cover -func=coverage.out | tail -1
	@echo "✓ Coverage report: coverage.html"

# ── Build & Release ──

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

release: cross-compile
	@echo "📋 Generating checksums..."
	cd $(BUILD_DIR) && shasum -a 256 * > checksums.txt
	@echo "✓ Release ready in $(BUILD_DIR)/"
	@cat $(BUILD_DIR)/checksums.txt

goreleaser-check:
	@echo "🔧 Checking GoReleaser config..."
	goreleaser check
	@echo "✓ Config valid"

goreleaser-snapshot:
	@echo "📸 Building snapshot release..."
	goreleaser release --snapshot --clean
	@echo "✓ Snapshot ready in $(BUILD_DIR)/"

# ── Docker ──

docker-build:
	@echo "🐳 Building Docker image..."
	docker build -t tito:$(VERSION) -t tito:latest .
	@echo "✓ Image: tito:$(VERSION)"

docker-push: docker-build
	@echo "🚀 Pushing to GHCR..."
	docker tag tito:$(VERSION) ghcr.io/leathal1/tito:$(VERSION)
	docker tag tito:latest ghcr.io/leathal1/tito:latest
	docker push ghcr.io/leathal1/tito:$(VERSION)
	docker push ghcr.io/leathal1/tito:latest
	@echo "✓ Pushed"

docker-run:
	@echo "🐳 Running TITO in Docker..."
	docker run --rm -v $(PWD):/workspace tito:latest scan --repo /workspace

# ── Analysis ──

self-scan: build
	@echo "🛡️ Running TITO on itself..."
	./$(BINARY_NAME) scan --repo . --maestro --mitre --attack-paths --output self-scan.md
	@echo "✓ Self-scan: self-scan.md"

sarif: build
	@echo "📋 Generating SARIF output..."
	./$(BINARY_NAME) scan --repo . --output tito-results.sarif --format sarif 2>/dev/null || \
		echo "⚠️  SARIF output not yet implemented — coming in TITO Pro"

badge: build
	@echo "🏷️ Generating badge..."
	@./scripts/generate-badge.sh self-scan.md 2>/dev/null || echo "Run 'make self-scan' first"

# ── Demo ──

demo:
	@echo "🎯 Running demo scan..."
	go run ./cmd/tito scan --repo https://github.com/OWASP/NodeGoat --maestro --semgrep --mitre --dataflow
	@echo "✓ Demo complete"

# ── Help ──

help:
	@echo "TITO v$(VERSION) — Threat In, Threat Out"
	@echo ""
	@echo "Core:"
	@echo "  make build          Build binary"
	@echo "  make test           Run tests with race detection"
	@echo "  make install        Install to GOPATH"
	@echo "  make clean          Remove build artifacts"
	@echo ""
	@echo "Quality:"
	@echo "  make lint           Run golangci-lint"
	@echo "  make vet            Run go vet"
	@echo "  make fmt            Format code"
	@echo "  make coverage       Generate coverage report"
	@echo ""
	@echo "Release:"
	@echo "  make cross-compile  Build all platforms"
	@echo "  make release        Cross-compile + checksums"
	@echo "  make goreleaser-check  Validate .goreleaser.yml"
	@echo "  make goreleaser-snapshot  Build snapshot release"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build   Build Docker image"
	@echo "  make docker-push    Push to GHCR"
	@echo "  make docker-run     Run scan in Docker"
	@echo ""
	@echo "Analysis:"
	@echo "  make self-scan      Run TITO on itself"
	@echo "  make sarif          Generate SARIF output"
	@echo "  make badge          Generate shields.io badge"
	@echo "  make demo           Run demo on OWASP NodeGoat"
