# 🛡️ TITO — Threat In, Threat Out

> *Continuous threat intelligence that sees what scanners miss.*

**Single binary. Point at a repo. Get a visual threat model.**

TITO combines **STRIDE-LM**, **MAESTRO** (agentic AI security), **Semgrep** SAST, and **MITRE ATT&CK** mapping into one tool — with interactive data flow diagrams that actually look good.

![Data Flow Diagram](docs/screenshot.png)

## Why TITO?

| Feature | TITO | Microsoft TMT | OWASP Threat Dragon | IriusRisk |
|---------|------|---------------|---------------------|-----------|
| STRIDE-LM | ✅ | STRIDE only | STRIDE only | STRIDE only |
| MAESTRO (AI/Agent) | ✅ | ❌ | ❌ | ❌ |
| SAST Integration | ✅ Semgrep | ❌ | ❌ | Limited |
| MITRE ATT&CK | ✅ | ❌ | ❌ | Limited |
| Visual Data Flow | ✅ Interactive D3.js | Basic | Basic | Basic |
| CLI / CI/CD | ✅ Single binary | ❌ GUI only | ❌ Web only | ❌ SaaS |
| Runs Anywhere | ✅ Mac/Linux/Windows | Windows only | Browser | Cloud |

## Quick Start

```bash
# Install
go install github.com/Leathal1/TITO/cmd/atip@latest

# Scan a repository (full analysis)
atip scan \
  --repo https://github.com/your/app \
  --maestro \
  --semgrep \
  --mitre \
  --dataflow \
  --output threat-model.html

# Open the interactive diagram
open threat-model.html
```

## What You Get

### 1. Threat Report
Detailed markdown report with:
- STRIDE-LM classification (Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation, Lateral Movement, Malware)
- MAESTRO agentic AI analysis across 7 layers
- MITRE ATT&CK technique mappings
- Semgrep SAST findings
- Risk-scored, prioritized findings

### 2. Interactive Data Flow Diagram
Self-contained HTML file with:
- 🌙 Dark theme — designed for presentations
- 🎯 Color-coded risk levels (critical → low)
- ⚡ Animated data flows between components
- 🔒 Trust boundary visualization
- 📊 Click any node for threat details
- 📤 Export to SVG

## The Frameworks

### STRIDE-LM (Traditional Threat Modeling)
Extended STRIDE with Lateral Movement and Malware categories. Maps threats via keyword analysis, CWE IDs, and MITRE ATT&CK tactics.

### MAESTRO (Agentic AI Security)
Cloud Security Alliance's 7-layer framework for AI agent threat modeling:

| Layer | Focus |
|-------|-------|
| 1. Foundation Models | Prompt injection, jailbreaking, model theft |
| 2. Data & Knowledge | RAG poisoning, embedding attacks |
| 3. Agent Frameworks | LangChain/CrewAI exploits, memory manipulation |
| 4. Tooling & Integration | MCP attacks, API abuse, tool poisoning |
| 5. Agent Communication | Trust exploitation, message spoofing |
| 6. Deployment & Infra | Container escapes, sandbox bypasses |
| 7. Ecosystem & Governance | Compliance gaps, accountability |

### Semgrep SAST
Runs Semgrep static analysis and maps findings to STRIDE-LM categories and MAESTRO layers automatically via CWE mappings.

### MITRE ATT&CK
Every finding enriched with relevant ATT&CK techniques across all 12 tactics.

## CI/CD Integration

### GitHub Actions

```yaml
- name: TITO Threat Model
  run: |
    atip scan \
      --repo . \
      --maestro \
      --semgrep \
      --mitre \
      --dataflow \
      --output threat-model.html

- name: Upload Diagram
  uses: actions/upload-artifact@v4
  with:
    name: threat-model
    path: threat-model.html
```

Your threat model updates on every push. Living documentation.

## Build from Source

```bash
git clone https://github.com/Leathal1/TITO.git
cd TITO
make build        # Build for current platform
make test         # Run all tests
make cross-compile # Build for all platforms
make release      # Build + checksums
```

## Architecture

```
TITO Pipeline:
┌──────────┐   ┌───────────┐   ┌──────────┐   ┌───────────┐
│ Scan Repo │──▶│ Classify  │──▶│  Enrich  │──▶│ Visualize │
│           │   │           │   │          │   │           │
│ • Assets  │   │ • STRIDE  │   │ • ATT&CK │   │ • D3.js   │
│ • Flows   │   │ • MAESTRO │   │ • Semgrep│   │ • Reports │
│ • Deps    │   │ • NVD/CVE │   │ • CWE    │   │ • HTML    │
└──────────┘   └───────────┘   └──────────┘   └───────────┘
```

## Contributing

PRs welcome. Run `make test` before submitting.

## License

MIT

---

*Built by [@gorillainfosec](https://x.com/gorillainfosec) — "The best defense is built by those who truly understand offense."*
