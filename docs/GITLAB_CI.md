# TITO — GitLab CI Integration

## Quick Start

Add TITO to your `.gitlab-ci.yml`:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/Leathal1/TITO/main/.gitlab/tito-scan.gitlab-ci.yml'
```

That's it. TITO will run on every merge request and default branch push.

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TITO_FAIL_ON` | `never` | Fail threshold: `critical`, `high`, `medium`, `any`, `never` |
| `TITO_OUTPUT` | `threat-model.md` | Output file path |
| `TITO_MAESTRO` | `false` | Enable MAESTRO agentic AI analysis |
| `TITO_MITRE` | `false` | Enable MITRE ATT&CK mapping |
| `TITO_SEMGREP` | `false` | Enable Semgrep SAST integration |
| `TITO_ATTACK_PATHS` | `true` | Enable attack path analysis |

### Full Scan Example

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/Leathal1/TITO/main/.gitlab/tito-scan.gitlab-ci.yml'

tito-scan:
  variables:
    TITO_MAESTRO: "true"
    TITO_MITRE: "true"
    TITO_SEMGREP: "true"
    TITO_FAIL_ON: "critical"
```

## Threat Diff for Merge Requests

For merge request threat diffing, include the diff template:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/Leathal1/TITO/main/.gitlab/tito-diff.gitlab-ci.yml'
```

This compares the target branch against your MR changes and reports new/resolved threats.

### Both Scan + Diff

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/Leathal1/TITO/main/.gitlab/tito-scan.gitlab-ci.yml'
  - remote: 'https://raw.githubusercontent.com/Leathal1/TITO/main/.gitlab/tito-diff.gitlab-ci.yml'

tito-scan:
  variables:
    TITO_MAESTRO: "true"
    TITO_FAIL_ON: "high"

tito-diff:
  variables:
    TITO_FAIL_ON: "critical"
```

## Using Docker Image

If you prefer the Docker approach:

```yaml
tito-scan:
  image: ghcr.io/leathal1/tito:latest
  stage: test
  script:
    - tito scan --repo . --maestro --mitre --output report.md
  artifacts:
    paths: [report.md]
```

## Artifacts

Both templates save reports as GitLab CI artifacts (30 day retention):
- `threat-model.md` — Full scan report
- `threat-diff.md` — MR threat delta

---

> 🔒 **TITO Pro** — Compliance profiles (PCI DSS 4.0, HIPAA, SOC2), LLM-powered deep analysis, and custom report templates. Coming soon.
