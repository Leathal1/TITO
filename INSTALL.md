# TITO Installation Guide

## Quick Install

### Option 1: Go Install (recommended)

Requires Go 1.21+:

```bash
go install github.com/Leathal1/TITO/cmd/tito@latest
```

### Option 2: Download Binary

Download a prebuilt binary from [GitHub Releases](https://github.com/Leathal1/TITO/releases):

```bash
# Example for Linux amd64
curl -fsSL https://github.com/Leathal1/TITO/releases/latest/download/tito-linux-amd64 -o tito
chmod +x tito
sudo mv tito /usr/local/bin/
```

Available binaries:
- `tito-darwin-amd64` (macOS Intel)
- `tito-darwin-arm64` (macOS Apple Silicon)
- `tito-linux-amd64`
- `tito-linux-arm64`
- `tito-windows-amd64.exe`

### Option 3: Build from Source

```bash
git clone https://github.com/Leathal1/TITO.git
cd TITO
make build
```

The binary will be in the project root. Move it to your PATH:

```bash
sudo mv tito /usr/local/bin/
```

## Verify Installation

```bash
tito --help
tito version
```

## Optional: Semgrep

TITO integrates with [Semgrep](https://semgrep.dev/) for static analysis. Semgrep is auto-installed when needed, or you can install it manually:

```bash
tito semgrep install
```

Or install directly via pip/brew:

```bash
pip install semgrep
# or
brew install semgrep
```

## Configuration

```bash
# Initialize a config file in the current directory
tito init-config

# Set NVD API key for higher rate limits (optional)
export NVD_API_KEY="your-api-key-here"
```

Get an NVD API key from: https://nvd.nist.gov/developers/request-an-api-key

## Usage

```bash
# Scan a repository
tito scan --repo .

# Full scan with all features
tito scan --repo . --maestro --semgrep --mitre --dataflow --output threat-model.html

# Check system status
tito status
```

## GitHub Action

Add to your workflow:

```yaml
- uses: Leathal1/TITO@v2
  with:
    maestro: true
    semgrep: true
    mitre: true
```

See [action.yml](action.yml) for all options.

## Upgrading

```bash
go install github.com/Leathal1/TITO/cmd/tito@latest
```

Or download the latest binary from [Releases](https://github.com/Leathal1/TITO/releases).

## Getting Help

- Documentation: See [README.md](README.md) and [ARCHITECTURE.md](ARCHITECTURE.md)
- Issues: https://github.com/Leathal1/TITO/issues
- CLI help: `tito --help`
