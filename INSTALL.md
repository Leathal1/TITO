# TITO Installation Guide

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

3. **Install TITO**

```bash
pip install -e .
```

This installs TITO in editable mode with all dependencies.

4. **Verify installation**

```bash
tito --help
```

You should see the TITO CLI help message.

## Configuration

1. **Create configuration file**

```bash
tito init-config
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
export DATABASE_URL="postgresql://user:pass@localhost/tito"

# Log level
export LOG_LEVEL="INFO"
```

Get an NVD API key from: https://nvd.nist.gov/developers/request-an-api-key

## Usage

### Collect Threat Intelligence

```bash
# Run all collectors
tito collect --all

# Run specific collectors
tito collect --nvd
tito collect --osint
tito collect --nvd --osint
```

### Generate Reports

```bash
# Generate markdown report
tito report

# Generate JSON report
tito report -f json -o report.json

# Generate from saved threats
tito collect --all --output threats.json
tito report -i threats.json
```

### Check System Status

```bash
tito status
```

### Start API Server

```bash
tito serve --host 0.0.0.0 --port 8080
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
black tito/
```

### Type Checking

```bash
mypy tito/
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

Try the demonstration script to see TITO in action:

```bash
python examples/demo.py
```

This demonstrates:
- STRIDE-LM classification
- Threat collection and processing
- Intelligence lifecycle

## Troubleshooting

### Import Errors

If you get import errors, ensure TITO is installed:

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
docker build -t tito:latest .

# Run container
docker run -p 8080:8080 tito:latest
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
Description=TITO Threat Intelligence Platform
After=network.target

[Service]
Type=simple
User=tito
WorkingDirectory=/opt/tito
Environment="TITO_CONFIG=/etc/tito/config.yaml"
ExecStart=/opt/tito/venv/bin/tito serve
Restart=always

[Install]
WantedBy=multi-user.target
```

## Upgrading

To upgrade TITO:

```bash
git pull origin main
pip install -e . --upgrade
```

## Uninstallation

To remove TITO:

```bash
pip uninstall tito
```

## Getting Help

- Documentation: See README.md and ARCHITECTURE.md
- Issues: Report at https://github.com/yourusername/TITO/issues
- CLI help: `tito --help`

---

**Next Steps After Installation:**

1. Run `tito status` to verify configuration
2. Run `tito collect --all` to collect initial threats
3. Run `tito report` to generate your first intelligence report
4. Explore `examples/demo.py` to understand the system

*Welcome to TITO - Let's transform chaos into clarity.*
