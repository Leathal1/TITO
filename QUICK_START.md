# TITO Quick Start Guide

## New Features Available

TITO now includes advanced threat modeling capabilities:

1. **MAESTRO** - 7-layer agentic AI threat classification
2. **MITRE ATT&CK** - Maps threats to adversary techniques
3. **Semgrep** - Static code analysis integration
4. **Data Flow Diagrams** - Beautiful interactive visualizations

## Installation

```bash
# Build TITO
cd /Users/stevenleath/TITO
go build ./cmd/tito

# Verify installation
./tito version
```

## Basic Usage

### 1. Scan with All Features

```bash
./tito scan \
  --repo https://github.com/user/repository \
  --maestro \
  --semgrep \
  --mitre \
  --dataflow \
  --output threat-model.html
```

This will:
- ✅ Clone and scan the repository
- ✅ Run MAESTRO agentic AI analysis
- ✅ Execute Semgrep static analysis
- ✅ Map threats to MITRE ATT&CK
- ✅ Generate interactive data flow diagram

### 2. AI/Agent Systems (MAESTRO Focus)

```bash
./tito scan \
  --repo https://github.com/user/ai-agent \
  --maestro \
  --dataflow
```

Best for:
- LangChain/AutoGen/CrewAI applications
- RAG systems
- Multi-agent systems
- AI tool integrations

### 3. Traditional Apps (STRIDE-LM + Semgrep)

```bash
./tito scan \
  --repo https://github.com/user/web-app \
  --semgrep \
  --mitre
```

Best for:
- Web applications
- APIs
- Microservices
- Traditional architectures

## Example Output

### Console Output

```
🔍 TITO Repository Scanner
==================================================

📂 Cloning repository: https://github.com/user/repo
   Branch: main

✓ Repository scanned successfully
  Language: go
  Framework: gin
  Assets discovered: 23
  Data flows: 12
  Dependencies: 45

🔍 Collecting threat intelligence...
✓ Collected 15 threats

🤖 Running MAESTRO agentic AI threat analysis...
✓ MAESTRO Classification: 3-Frameworks
  Identified Threats: 8

🔬 Running Semgrep static analysis...
✓ Semgrep found 42 issues (12 WARNING+)
  Mapped to 5 threat categories

🎯 Mapping threats to code assets...
✓ Mapped 15 threats to code

🎯 Enriching with MITRE ATT&CK mappings...
✓ ATT&CK techniques mapped

📊 Generating interactive data flow diagram...
✓ Interactive diagram generated: threat-model.html
  Open in browser to explore!

📊 Results Summary:
--------------------------------------------------
  🔴 Critical threats: 2
  🟠 High threats: 5
  📦 Total affected assets: 18
  🔄 Risky data flows: 7
  🔬 Semgrep findings: 42

Top 5 Threats:
  1. [critical] [T(I)] SQL Injection via user input (Risk: 0.92)
  2. [high] [S] Authentication bypass in API (Risk: 0.85)
  ...

💡 Next steps:
   Open threat-model.html in your browser
   tito dashboard                     # Launch web dashboard
```

### Interactive Diagram

Open `threat-model.html` in your browser to see:
- **Nodes** - Color-coded by risk level (red → critical, orange → high, yellow → medium, green → low)
- **Edges** - Data flows with sensitivity indicators
- **Trust Boundaries** - Security zones visualization
- **Interactive** - Click nodes to see detailed findings
- **Animated** - Pulsing critical nodes, flowing data streams

## MAESTRO Layer Reference

1. **Foundation Models** - Prompt injection, jailbreaking, model theft
2. **Data & Knowledge** - RAG poisoning, embedding attacks
3. **Agent Frameworks** - LangChain/AutoGen exploits
4. **Tooling & Integration** - MCP server attacks, API abuse
5. **Agent Communication** - Multi-agent trust exploitation
6. **Deployment & Infrastructure** - Container escapes, resource exhaustion
7. **Ecosystem & Governance** - Compliance gaps, audit manipulation

## MITRE ATT&CK Integration

Threats are automatically mapped to:
- **Tactics** - Initial Access, Execution, Persistence, Privilege Escalation, etc.
- **Techniques** - Specific attack methods (T1190, T1059, T1078, etc.)
- **Detection** - How to detect the technique
- **Mitigation** - How to prevent/mitigate

## Semgrep Integration

Automatically runs:
```bash
semgrep scan --json --config auto <path>
```

Findings are:
- Filtered by severity (ERROR, WARNING, INFO)
- Mapped to STRIDE-LM categories
- Mapped to MAESTRO layers (for AI code)
- Enriched with CWE IDs and OWASP categories

## Configuration

Default config at `config.yaml`:

```yaml
collectors:
  nvd:
    enabled: true
    api_key: ""
    days_back: 7

pipeline:
  min_priority: 0.5
  max_age_days: 30
```

## Troubleshooting

### Semgrep not found
```bash
# Install Semgrep
pip install semgrep
# or
brew install semgrep
```

### Repository clone fails
- Check git access/credentials
- Try with HTTPS URL instead of SSH
- Ensure branch exists

### No threats found
- Increase `days_back` in config
- Lower `min_priority` threshold
- Check NVD API connectivity

## Advanced Usage

### Custom Semgrep Rules
```bash
# Create custom rules in .semgrep/
./tito scan --repo <url> --semgrep
```

### Export Data Flow Diagram
```bash
# Open HTML, click "Export SVG" button
# Or use browser tools: File → Save As → SVG
```

### Combine with Dashboard
```bash
# Run scan first
./tito scan --repo <url> --maestro --semgrep

# Launch dashboard
./tito dashboard --port 8080
```

## Next Steps

1. **Try it out** - Run a scan on your codebase
2. **Explore the diagram** - Open the HTML visualization
3. **Review findings** - Check MAESTRO/MITRE/Semgrep results
4. **Iterate** - Fix issues and rescan

---

**Need Help?**
- Check `./tito --help` for all commands
- See `FEATURES.md` for technical details
- Review test files for usage examples
