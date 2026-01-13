.PHONY: build install clean test fmt vet run-demo help

# Build variables
BINARY_NAME=atip
INSTALL_PATH=/usr/local/bin

# Go commands
GOCMD=go
GOBUILD=$(GOCMD) build
GOINSTALL=$(GOCMD) install
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOFMT=$(GOCMD) fmt
GOVET=$(GOCMD) vet
GOMOD=$(GOCMD) mod

help: ## Show this help message
	@echo 'Usage:'
	@echo '  make [target]'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the binary
	@echo "Building $(BINARY_NAME)..."
	$(GOBUILD) -o $(BINARY_NAME) ./cmd/atip
	@echo "✓ Build complete: ./$(BINARY_NAME)"

install: build ## Install the binary to /usr/local/bin
	@echo "Installing to $(INSTALL_PATH)/$(BINARY_NAME)..."
	@cp $(BINARY_NAME) $(INSTALL_PATH)/$(BINARY_NAME)
	@echo "✓ Installed successfully"

clean: ## Remove build artifacts
	@echo "Cleaning..."
	$(GOCLEAN)
	@rm -f $(BINARY_NAME)
	@rm -rf reports/
	@echo "✓ Clean complete"

test: ## Run tests
	@echo "Running tests..."
	$(GOTEST) -v ./...

fmt: ## Format code
	@echo "Formatting code..."
	$(GOFMT) ./...
	@echo "✓ Format complete"

vet: ## Run go vet
	@echo "Running go vet..."
	$(GOVET) ./...
	@echo "✓ Vet complete"

deps: ## Download dependencies
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy
	@echo "✓ Dependencies ready"

run-demo: build ## Run the demo
	@echo "Running demo..."
	$(GOCMD) run ./examples/demo/main.go

init-config: build ## Initialize configuration file
	@echo "Creating default configuration..."
	./$(BINARY_NAME) init-config
	@echo "✓ Configuration created"

collect: build ## Run threat collection
	@echo "Running threat collection..."
	./$(BINARY_NAME) collect --all

report: build ## Generate threat report
	@echo "Generating threat report..."
	./$(BINARY_NAME) report

status: build ## Show system status
	@echo "System status:"
	./$(BINARY_NAME) status

all: clean deps build ## Clean, download deps, and build

.DEFAULT_GOAL := help
