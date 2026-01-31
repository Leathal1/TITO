# 🛡️ TITO — Threat In, Threat Out

> **The threat modeler that thinks like an attacker.**

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Threat Model](https://github.com/Leathal1/TITO/actions/workflows/tito-scan.yml/badge.svg)](https://github.com/Leathal1/TITO/actions/workflows/tito-scan.yml)

Single binary. Point at a repo. Get **attack path analysis**, **3D threat visualization**, **STRIDE-LM + MAESTRO classification**, and **MITRE ATT&CK mappings** — all in one scan.

<p align="center">
  <img src="docs/screenshots/3d-hero.png" alt="TITO 3D Threat Model Visualization" width="900">
</p>

---

## Why TITO?

Every other threat modeling tool makes you draw diagrams by hand. TITO **reads your code** and builds the threat model for you — then chains findings into **realistic multi-step attack paths**.

| Feature | TITO | Microsoft TMT | OWASP Threat Dragon | IriusRisk |
|---------|:----:|:-------------:|:-------------------:|:---------:|
| **STRIDE-LM** | ✅ | STRIDE only | STRIDE only | STRIDE only |
| **MAESTRO** (AI/Agent threats) | ✅ | ❌ | ❌ | ❌ |
| **Attack Path Analysis** | ✅ | ❌ | ❌ | ❌ |
| **3D Visualization** | ✅ | ❌ | ❌ | ❌ |
| **SAST Integration** | ✅ Semgrep | ❌ | ❌ | Limited |
| **MITRE ATT&CK** | ✅ | ❌ | ❌ | Limited |
| **PR Threat Diffing** | ✅ | ❌ | ❌ | ❌ |
| **Interactive Data Flow** | ✅ D3.js + Three.js | Basic | Basic | Basic |
| **CLI / CI/CD** | ✅ Single binary | ❌ GUI only | ❌ Web only | ❌ SaaS |
| **Runs Anywhere** | ✅ Mac/Linux/Windows | Windows only | Browser | Cloud |

---

## Quick Start

```bash
# Install
go install github.com/Leathal1/TITO/cmd/tito@latest

# Scan a repository
tito scan --repo https://github.com/your/app

# Full analysis with all frameworks
tito scan \
  --repo https://github.com/your/app \
  --maestro \
  --mitre \
  --attack-paths \
  --3d \
  --output threat-model.html

# Open the interactive 3D visualization
open threat-model.html
```

```
🔍 TITO Repository Scanner
==================================================

📂 Cloning repository: https://github.com/your/app

✓ Repository scanned successfully
  Assets discovered: 655
  Data flows: 5205

🔍 Analyzing code for security threats...
✓ Total processed threats: 19

🤖 Running MAESTRO agentic AI threat analysis...
✓ MAESTRO Classification complete

🎯 Enriching with MITRE ATT&CK mappings...
✓ ATT&CK techniques mapped

📊 Results Summary:
--------------------------------------------------
  🔴 Critical threats: 8
  🟠 High threats: 6
  🟡 Medium threats: 3
  🟢 Low threats: 2
  📦 Total affected assets: 655
  🔄 Data flows analyzed: 5205
```

---

## Features

### ⚔️ Attack Path Analysis

**Like BloodHound, but for application-layer threat models.**

TITO chains individual findings into realistic multi-step attack paths — answering: *"If an attacker lands here, what's the worst-case path to crown jewels?"*

```bash
tito attack-paths --repo . --top 5 --3d --narrative
```

Each path shows:
- **Entry point** → intermediate steps → **crown jewel** (databases, secrets, admin APIs)
- Chained MITRE ATT&CK techniques at each hop
- Cumulative risk score across the kill chain
- Human-readable **narrative** explaining the attack story

Attack paths overlay directly onto the 3D visualization — red glowing trails showing exactly how an attacker would move through your system.

### 🌐 3D Threat Visualization

Interactive Three.js visualization with:
- **Color-coded nodes** by risk severity (🔴 critical → 🟢 low)
- **Animated data flows** between components
- **Trust boundaries** as translucent shells
- **Attack path overlays** with glowing particle trails
- **Click any node** for full threat details
- **Dark theme** — designed for presentations
- Export to screenshot

<p align="center">
  <img src="docs/screenshots/3d-viz.png" alt="TITO 3D Visualization with Controls" width="900">
</p>

Also generates **2D interactive diagrams** (D3.js) with the `--dataflow` flag.

### 🔀 PR Threat Diffing

Run `tito diff` in CI to catch security regressions on every pull request:

```bash
tito diff --repo . --base main --head feature-branch --format markdown
```

Output:
```markdown
## 🛡️ TITO Threat Model Delta

**Risk: ⬆️ INCREASED** (6.2 → 7.8) | Verdict: ⚠️ WARN

### ⚠️ New Threats (2)
- 🔴 SQL Injection in /api/admin/users [CRITICAL]
- 🟠 Unauthenticated endpoint exposed [HIGH]
```

Exit codes for CI gates:
- **0** = PASS — no new threats or risk decreased
- **1** = WARN — new threats detected (non-critical)
- **2** = FAIL — critical security regression

See [docs/DIFF.md](docs/DIFF.md) for full documentation.

### 🎯 STRIDE-LM

Extended STRIDE with **Lateral Movement** and **Malware** categories. Maps threats via keyword analysis, CWE IDs, and MITRE ATT&CK tactics.

| Category | What it Catches |
|----------|----------------|
| **S**poofing | Authentication bypasses, identity issues |
| **T**ampering | Data/code modification, integrity violations |
| **R**epudiation | Missing audit trails, log gaps |
| **I**nfo Disclosure | Data leaks, credential exposure, PII |
| **D**enial of Service | Resource exhaustion, crash vectors |
| **E**levation of Privilege | Authz bypasses, privilege escalation |
| **L**ateral Movement | Internal pivoting, trust exploitation |
| **M**alware | Supply chain attacks, code injection |

### 🤖 MAESTRO (Agentic AI Security)

Cloud Security Alliance's 7-layer framework for AI agent threat modeling — the only CLI tool that implements it:

| Layer | Focus |
|-------|-------|
| 1. Foundation Models | Prompt injection, jailbreaking, model theft |
| 2. Data & Knowledge | RAG poisoning, embedding attacks |
| 3. Agent Frameworks | LangChain/CrewAI exploits, memory manipulation |
| 4. Tooling & Integration | MCP attacks, API abuse, tool poisoning |
| 5. Agent Communication | Trust exploitation, message spoofing |
| 6. Deployment & Infra | Container escapes, sandbox bypasses |
| 7. Ecosystem & Governance | Compliance gaps, accountability |

### 🔬 Semgrep + MITRE ATT&CK

- Runs **Semgrep** static analysis and maps findings to STRIDE-LM categories via CWE mappings
- Every finding enriched with relevant **ATT&CK techniques** across all 12 tactics
- Enable with `--semgrep` and `--mitre` flags

---

## Real World: JoonaPay Fintech Audit

TITO scanned a production fintech payments platform:

| Metric | Result |
|--------|--------|
| **Assets discovered** | 655 |
| **Data flows mapped** | 5,205 |
| **Threats identified** | 19 |
| **Critical severity** | 8 |
| **High severity** | 6 |
| **Attack paths found** | 10 |
| **Scan time** | ~45 seconds |

Key findings included hardcoded credentials, unauthenticated payment APIs, and a 4-hop attack path from a public endpoint through message queues to the payment database.

**Zero manual diagram drawing. Zero configuration files. Just `tito scan`.**

---

## Free vs Pro vs Enterprise

| | **Free** | **Pro** ($29/mo) | **Enterprise** |
|---|:---:|:---:|:---:|
| Repository scanning | ✅ | ✅ | ✅ |
| STRIDE-LM classification | ✅ | ✅ | ✅ |
| 2D Data flow diagrams | ✅ | ✅ | ✅ |
| Semgrep integration | ✅ | ✅ | ✅ |
| MITRE ATT&CK mapping | ✅ | ✅ | ✅ |
| **MAESTRO** (AI threats) | — | ✅ | ✅ |
| **Attack path analysis** | — | ✅ | ✅ |
| **3D visualization** | — | ✅ | ✅ |
| **PR threat diffing** | — | ✅ | ✅ |
| **Attack narratives** | — | ✅ | ✅ |
| API server | — | — | ✅ |
| Compliance mapping | — | — | ✅ |
| Web dashboard | — | — | ✅ |
| Team management | — | — | ✅ |
| Priority support | — | — | ✅ |

The free tier is a fully functional threat modeler. Pro unlocks the features that make TITO different.

---

## CI/CD Integration

### GitHub Actions

```yaml
name: TITO Threat Model
on:
  pull_request:
    branches: [main]

jobs:
  threat-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-go@v5
        with:
          go-version: '1.21'

      - name: Install TITO
        run: go install github.com/Leathal1/TITO/cmd/tito@latest

      - name: Threat Model Diff
        run: |
          tito diff \
            --repo . \
            --base ${{ github.base_ref }} \
            --head ${{ github.head_ref }} \
            --format markdown \
            --output threat-diff.md \
            --fail-on critical

      - name: Comment on PR
        if: always()
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const body = fs.readFileSync('threat-diff.md', 'utf8');
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: body
            });

      - name: Full Scan + 3D Visualization
        run: |
          tito scan \
            --repo . \
            --maestro \
            --mitre \
            --attack-paths \
            --3d \
            --output threat-model.html

      - name: Upload Artifact
        uses: actions/upload-artifact@v4
        with:
          name: threat-model
          path: threat-model.html
```

Your threat model updates on every push. Living documentation.

### GitLab CI / Jenkins

See [docs/DIFF.md](docs/DIFF.md) for GitLab CI and Jenkins examples.

---

## Build from Source

```bash
git clone https://github.com/Leathal1/TITO.git
cd TITO
make build          # Build for current platform
make test           # Run all tests
make cross-compile  # Build for all platforms
make release        # Build + checksums
```

## Architecture

```
TITO Pipeline:
┌──────────┐   ┌───────────┐   ┌──────────┐   ┌───────────┐   ┌─────────────┐
│ Scan Repo │──▶│ Classify  │──▶│  Enrich  │──▶│  Analyze  │──▶│  Visualize  │
│           │   │           │   │          │   │           │   │             │
│ • Assets  │   │ • STRIDE  │   │ • ATT&CK │   │ • Attack  │   │ • 3D/Three  │
│ • Flows   │   │ • MAESTRO │   │ • Semgrep│   │   Paths   │   │ • 2D/D3.js  │
│ • Deps    │   │ • NVD/CVE │   │ • CWE    │   │ • Chains  │   │ • Reports   │
└──────────┘   └───────────┘   └──────────┘   └───────────┘   └─────────────┘
```

## All Commands

```
tito scan           Scan a repository for threats and assets
tito attack-paths   Generate attack path analysis and kill chain visualization
tito diff           Compare threat models between two scans (PR diff)
tito report         Generate threat report from scan results
tito serve          Serve a TITO report or diagram in the browser
tito status         Show TITO system status and license tier
tito dashboard      Start the web dashboard (Enterprise)
tito api            Start the TITO API server (Enterprise)
tito compliance     Map threats to compliance frameworks (Enterprise)
```

## Contributing

PRs welcome. Run `make test` before submitting.

## License

MIT

---

<p align="center">
  <i>Built by <a href="https://x.com/gorillainfosec">@gorillainfosec</a> — "The best defense is built by those who truly understand offense."</i>
</p>
