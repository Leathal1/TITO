# ATIP Installation Guide

## Quick Start

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Git

### Installation

1. **Clone the repository**

```bash
git clone https://github.com/yourusername/TITO.git
cd TITO
```

2. **Create a virtual environment** (recommended)

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install ATIP**

```bash
pip install -e .
```

This installs ATIP in editable mode with all dependencies.

4. **Verify installation**

```bash
atip --help
```

You should see the ATIP CLI help message.

## Configuration

1. **Create configuration file**

```bash
atip init-config
```

This creates a `config.yaml` file in the current directory with default settings.

2. **Edit configuration**

```bash
# Copy example config
cp config/config.example.yaml config.yaml

# Edit with your preferred editor
nano config.yaml  # or vim, code, etc.
```

3. **Set environment variables** (optional)

```bash
# NVD API key (optional but recommended for higher rate limits)
export NVD_API_KEY="your-api-key-here"

# Database connection (if using PostgreSQL)
export DATABASE_URL="postgresql://user:pass@localhost/atip"

# Log level
export LOG_LEVEL="INFO"
```

Get an NVD API key from: https://nvd.nist.gov/developers/request-an-api-key

## Usage

### Collect Threat Intelligence

```bash
# Run all collectors
atip collect --all

# Run specific collectors
atip collect --nvd
atip collect --osint
atip collect --nvd --osint
```

### Generate Reports

```bash
# Generate markdown report
atip report

# Generate JSON report
atip report -f json -o report.json

# Generate from saved threats
atip collect --all --output threats.json
atip report -i threats.json
```

### Check System Status

```bash
atip status
```

### Start API Server

```bash
atip serve --host 0.0.0.0 --port 8080
```

## Development Installation

For development, install with dev dependencies:

```bash
pip install -e ".[dev]"
```

This includes:
- pytest (testing)
- black (code formatting)
- mypy (type checking)

### Running Tests

```bash
pytest
```

### Code Formatting

```bash
black atip/
```

### Type Checking

```bash
mypy atip/
```

## Optional Dependencies

### API Server

To use the API server features:

```bash
pip install ".[api]"
```

### PostgreSQL Support

For PostgreSQL database backend:

```bash
pip install ".[postgres]"
```

## Running the Demo

Try the demonstration script to see ATIP in action:

```bash
python examples/demo.py
```

This demonstrates:
- STRIDE-LM classification
- Threat collection and processing
- Intelligence lifecycle

## Troubleshooting

### Import Errors

If you get import errors, ensure ATIP is installed:

```bash
pip install -e .
```

### Permission Errors

If you get permission errors on Linux/Mac:

```bash
chmod +x examples/demo.py
```

### Database Errors

If using SQLite (default), ensure the directory is writable:

```bash
mkdir -p data
```

### Rate Limiting

If you're hitting NVD rate limits:

1. Get an API key: https://nvd.nist.gov/developers/request-an-api-key
2. Set it in config.yaml or environment variable

### Missing Dependencies

Install all dependencies explicitly:

```bash
pip install -r requirements.txt
```

## Docker Installation (Future)

Docker support is planned for future releases:

```bash
# Build image
docker build -t atip:latest .

# Run container
docker run -p 8080:8080 atip:latest
```

## Production Deployment

For production deployments:

1. **Use PostgreSQL** instead of SQLite
2. **Set strong API keys** for authentication
3. **Enable HTTPS** for API server
4. **Configure logging** to external systems
5. **Set up monitoring** and alerting
6. **Use systemd/supervisor** for process management
7. **Configure rate limiting** appropriately

Example systemd service file:

```ini
[Unit]
Description=ATIP Threat Intelligence Platform
After=network.target

[Service]
Type=simple
User=atip
WorkingDirectory=/opt/atip
Environment="ATIP_CONFIG=/etc/atip/config.yaml"
ExecStart=/opt/atip/venv/bin/atip serve
Restart=always

[Install]
WantedBy=multi-user.target
```

## Upgrading

To upgrade ATIP:

```bash
git pull origin main
pip install -e . --upgrade
```

## Uninstallation

To remove ATIP:

```bash
pip uninstall atip
```

## Getting Help

- Documentation: See README.md and ARCHITECTURE.md
- Issues: Report at https://github.com/yourusername/TITO/issues
- CLI help: `atip --help`

---

**Next Steps After Installation:**

1. Run `atip status` to verify configuration
2. Run `atip collect --all` to collect initial threats
3. Run `atip report` to generate your first intelligence report
4. Explore `examples/demo.py` to understand the system

*Welcome to ATIP - Let's transform chaos into clarity.*
