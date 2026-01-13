# ATIP - Advanced Threat Intelligence Platform

> *"We're not aggregating feeds. We're building an intelligence organism—something that breathes in chaos and exhales clarity."*

## The Vision

ATIP is a threat intelligence platform built on the STRIDE-LM framework. It transforms raw threat data into actionable intelligence that defenders can use to make critical decisions under pressure.

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
atip/
├── collectors/           # Intelligence collection modules
│   ├── cve/             # CVE/vulnerability feeds (NVD, etc.)
│   ├── osint/           # OSINT threat feeds
│   ├── malware/         # Malware signatures and IOCs
│   └── exploits/        # Exploit databases
├── core/                # Core intelligence engine
│   ├── models/          # Data models (threats, indicators, context)
│   ├── pipeline/        # Processing pipeline (normalize, enrich, dedupe)
│   ├── stride_lm/       # STRIDE-LM classification engine
│   └── enrichment/      # Context enrichment modules
├── analysis/            # Analysis engines
│   ├── correlation/     # Threat correlation and pattern matching
│   ├── scoring/         # Priority scoring algorithms
│   └── context/         # Contextual analysis (asset mapping, etc.)
├── dissemination/       # Output layer
│   ├── api/             # REST API for integration
│   ├── reports/         # Report generation (human-readable)
│   └── alerts/          # Alerting and notification system
├── storage/             # Data persistence
│   ├── database/        # Database models and migrations
│   └── cache/           # Caching layer for performance
├── config/              # Configuration management
├── cli/                 # Command-line interface
└── tests/              # Comprehensive test suite
```

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Configure
cp config/config.example.yaml config/config.yaml
# Edit config.yaml with your settings

# Initialize database
python -m atip.cli init-db

# Start collectors
python -m atip.cli collect --all

# Start API server
python -m atip.cli serve

# Generate report
python -m atip.cli report --format markdown --output report.md
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

## Development Philosophy

- **Simplicity Until It Hurts** — Expose complexity progressively, not immediately
- **Empathy for the User** — Design for the exhausted analyst at 3 AM
- **Craft Over Speed** — Better to ship intelligence than noise
- **Adversarial Mindset** — Think like an attacker, build for defenders

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
