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

### Option 3: Docker

```bash
# Pull the image
docker pull ghcr.io/leathal1/tito:latest

# Run a scan
docker run --rm -v "$(pwd):/workspace" ghcr.io/leathal1/tito:latest scan --repo /workspace

# Full analysis
docker run --rm -v "$(pwd):/workspace" ghcr.io/leathal1/tito:latest \
  scan --repo /workspace --maestro --mitre --attack-paths --output /workspace/threat-model.html
```

### Option 4: Build from Source

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

---

## CI/CD Integration

### GitHub Actions (Marketplace)

```yaml
- uses: Leathal1/TITO@v2
  with:
    maestro: true
    semgrep: true
    mitre: true
    sarif-output: true
```

See [action.yml](action.yml) for all options.

### GitHub Reusable Workflow

```yaml
jobs:
  threat-model:
    uses: Leathal1/TITO/.github/workflows/tito-reusable.yml@main
    with:
      maestro: true
      mitre: true
      sarif-output: true
```

### GitLab CI

See [GITLAB_CI.md](GITLAB_CI.md) for GitLab CI templates.

### Docker in CI

```yaml
# GitHub Actions
- name: TITO Scan
  run: |
    docker run --rm -v ${{ github.workspace }}:/workspace \
      ghcr.io/leathal1/tito:latest scan --repo /workspace --output /workspace/report.html
```

---

## Pre-commit Hook

### Option 1: Manual Install

```bash
cp scripts/pre-commit-tito.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

### Option 2: pre-commit Framework

Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/Leathal1/TITO
    rev: v2.1.0
    hooks:
      - id: tito-scan
```

Then install:

```bash
pip install pre-commit
pre-commit install
```

### Configuration

The pre-commit hook respects these environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `TITO_FAIL_ON` | `critical` | Fail threshold: critical, high, any, never |
| `TITO_SCAN_ARGS` | `--attack-paths` | Additional arguments to pass to `tito scan` |
| `TITO_QUIET` | `false` | Suppress informational output |

### Bypassing

To skip the hook for a single commit:

```bash
git commit --no-verify -m "your message"
```

---

## Upgrading

```bash
go install github.com/Leathal1/TITO/cmd/tito@latest
```

Or download the latest binary from [Releases](https://github.com/Leathal1/TITO/releases).

Or update the Docker image:

```bash
docker pull ghcr.io/leathal1/tito:latest
```

## Getting Help

- Documentation: See [README.md](README.md) and [ARCHITECTURE.md](ARCHITECTURE.md)
- Issues: https://github.com/Leathal1/TITO/issues
- CLI help: `tito --help`
