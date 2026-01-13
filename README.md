# ATIP - Advanced Threat Intelligence Platform

> *"We're not aggregating feeds. We're building an intelligence organism—something that breathes in chaos and exhales clarity."*

## The Vision

ATIP is a threat intelligence platform built in **pure Go** with the STRIDE-LM framework. It transforms raw threat data into actionable intelligence that defenders can use to make critical decisions under pressure.

**Built with Go for:**
- ⚡ **Performance** - Compiled, concurrent, blazing fast
- 📦 **Easy Deployment** - Single binary, zero dependencies
- 🔄 **Concurrency** - Goroutines for parallel collection and processing
- 🛡️ **Type Safety** - Strong typing for reliable data models
- 🚀 **Production Ready** - Battle-tested runtime and standard library

### Design Philosophy

**Think Like an Adversary** — Every piece of intel represents intent to cause harm. ATIP maps adversarial tradecraft to defender mental models.

**Signal-to-Noise Obsession** — The security industry drowns in data. ATIP is the filter that turns a firehose into a precision instrument.

**Craft Intelligence, Don't Aggregate Data** — There's a difference between "here's a CVE" and "here's why this CVE matters to *your* stack." ATIP delivers the latter.

**Build for the 3 AM Oncall** — Reports are read by exhausted humans making critical decisions. Every word reduces cognitive load.

## The STRIDE-LM Framework

```
┌─────────────────────────────────────────────────────────────────┐
│                    THE STRIDE-LM LENS                           │
├─────────────────────────────────────────────────────────────────┤
│  S — SPOOFING         "Who are you, really?"                    │
│      → Identity is the new perimeter                            │
│      → Credential leaks, auth bypasses, token forgery           │
├─────────────────────────────────────────────────────────────────┤
│  T — TAMPERING        "Can I trust what I'm seeing?"            │
│      → Data integrity is assumed until it isn't                 │
│      → Supply chain attacks, injection, MITM                    │
├─────────────────────────────────────────────────────────────────┤
│  R — REPUDIATION      "Did that really happen?"                 │
│      → Logs are your memory; memory can be erased               │
│      → Audit gaps, timestamp manipulation                       │
├─────────────────────────────────────────────────────────────────┤
│  I — INFO DISCLOSURE  "What's escaping?"                        │
│      → Secrets have gravity; they fall toward exposure          │
│      → Breaches, misconfigs, verbose errors                     │
├─────────────────────────────────────────────────────────────────┤
│  D — DENIAL OF SERVICE "Can you still operate?"                 │
│      → Availability is a security property                      │
│      → Resource exhaustion, amplification, logic DoS            │
├─────────────────────────────────────────────────────────────────┤
│  E — ELEVATION        "What can they reach now?"                │
│      → Every privilege is a blast radius                        │
│      → Privesc CVEs, misconfigs, confused deputies              │
├─────────────────────────────────────────────────────────────────┤
│  L — LATERAL MOVEMENT "Where are they going next?"              │
│      → Breach is a moment; compromise is a journey              │
│      → Pivoting, credential reuse, trust exploitation           │
├─────────────────────────────────────────────────────────────────┤
│  M — MALWARE          "What did they leave behind?"             │
│      → Code with hostile intent                                 │
│      → Implants, C2, persistence mechanisms                     │
└─────────────────────────────────────────────────────────────────┘
```

## Architecture

ATIP follows the intelligence lifecycle:

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  COLLECTION  │───>│  PROCESSING  │───>│   ANALYSIS   │
│              │    │              │    │              │
│ • CVE Feeds  │    │ • Normalize  │    │ • STRIDE-LM  │
│ • OSINT      │    │ • Enrich     │    │ • Correlate  │
│ • Malware    │    │ • Dedupe     │    │ • Score      │
└──────────────┘    └──────────────┘    └──────────────┘
                                               │
                                               v
┌──────────────┐                      ┌──────────────┐
│   FEEDBACK   │<─────────────────────│ DISSEMINATE  │
│              │                      │              │
│ • User Tags  │                      │ • API        │
│ • Actions    │                      │ • Reports    │
│ • Tuning     │                      │ • Alerts     │
└──────────────┘                      └──────────────┘
```

## Project Structure

```
.
├── cmd/
│   └── atip/                  # CLI application entry point
├── pkg/
│   ├── collectors/            # Intelligence collectors
│   │   ├── collector.go       # Base collector interface
│   │   └── nvd.go             # NVD CVE collector
│   ├── models/                # Data models
│   │   └── threat.go          # Threat, Indicator, Context models
│   ├── stridelm/              # STRIDE-LM classification
│   │   ├── categories.go      # Category definitions
│   │   └── classifier.go      # Classification engine
│   ├── pipeline/              # Processing pipeline
│   │   └── processor.go       # Multi-stage processor
│   ├── reports/               # Report generation
│   │   └── markdown.go        # Markdown report generator
│   ├── config/                # Configuration management
│   │   └── config.go          # Config loading and defaults
│   └── api/                   # API server (future)
├── examples/                  # Example code
├── config/                    # Configuration files
├── Makefile                   # Build automation
├── go.mod                     # Go module definition
└── README.md                  # This file
```

## Quick Start

### Prerequisites
- Go 1.21 or higher
- Make (optional)

### Installation

```bash
# Clone repository
git clone https://github.com/Leathal1/TITO.git
cd TITO

# Build the binary
make build
# Or: go build -o atip ./cmd/atip

# Initialize configuration
./atip init-config

# Edit configuration
vim config.yaml

# Collect threats
./atip collect --all

# Generate report
./atip report

# Check status
./atip status
```

## Core Principles

### 1. Signal Over Noise
Every alert that reaches a human should deserve to reach a human. Aggressive deduplication, intelligent scoring, and context-aware filtering ensure analysts see what matters.

### 2. Context is King
Raw indicators are useless without context. ATIP enriches every threat with:
- Asset relevance (does this affect YOUR stack?)
- Attack surface mapping (what's exposed?)
- Active exploitation status (is this being used in the wild?)
- Historical patterns (have we seen this before?)

### 3. Actionable Intelligence
Reports don't just describe threats—they prescribe actions. Each threat includes:
- Recommended mitigations
- Detection strategies
- Priority ranking against other threats
- Clear risk articulation

### 4. Continuous Learning
Feedback loops are first-class citizens. Analyst actions train the scoring system. False positives tune the filters. The system gets smarter with use.

## Why Go?

ATIP is built in Go to leverage its unique strengths for production security tooling:

- **Single Binary Deployment** - No dependencies, no runtime, just copy and run
- **Native Concurrency** - Goroutines enable parallel collection and processing
- **Compile-Time Safety** - Strong typing catches bugs before deployment
- **Fast Execution** - Compiled performance for large-scale threat processing
- **Cross-Platform** - Build for Linux, macOS, Windows from the same codebase
- **Excellent Tooling** - Built-in formatting, testing, profiling, and more
- **Production Ready** - Used by Kubernetes, Docker, Terraform, and other critical infrastructure

## Development

### Build Commands

```bash
make build          # Build binary
make install        # Install system-wide
make test           # Run tests
make fmt            # Format code
make vet            # Run linter
make clean          # Clean build artifacts
make all            # Clean, download deps, build
```

### Running Tests

```bash
go test -v ./...
```

### Code Formatting

```bash
go fmt ./...
```

## Contributing

ATIP is built with craftsmanship. PRs should:
- Include tests
- Update documentation
- Follow the existing architecture
- Demonstrate understanding of the intelligence lifecycle

## License

MIT

---

*"The best defense is built by those who truly understand offense."*
