# TITO GitLab CI/CD Integration

TITO provides ready-to-use GitLab CI templates for automated threat modeling in your merge request and deployment pipelines.

## Quick Start

### Option 1: Include from TITO Repository

Add this to your `.gitlab-ci.yml`:

```yaml
include:
  - project: 'Leathal1/TITO'
    file: '.gitlab/tito-scan.gitlab-ci.yml'
    ref: main
```

This adds a `tito-threat-model` job to the `test` stage that runs on every MR and default branch push.

### Option 2: Copy Templates

Copy the templates from `.gitlab/` into your repository and customize them.

---

## Templates

### Full Threat Scan (`.gitlab/tito-scan.gitlab-ci.yml`)

Runs a complete threat model scan including:
- STRIDE-LM threat classification
- MAESTRO agentic AI analysis
- MITRE ATT&CK technique mapping
- Attack path analysis
- 3D visualization (optional)

**Configuration variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `TITO_VERSION` | `latest` | TITO version to install |
| `TITO_MAESTRO` | `false` | Enable MAESTRO analysis |
| `TITO_MITRE` | `false` | Enable MITRE ATT&CK mapping |
| `TITO_SEMGREP` | `false` | Enable Semgrep SAST |
| `TITO_ATTACK_PATHS` | `true` | Enable attack path analysis |
| `TITO_3D` | `false` | Generate 3D visualization |
| `TITO_OUTPUT` | `threat-model.html` | Output file path |
| `TITO_FAIL_ON` | `never` | Fail threshold (critical, high, any, never) |

**Custom usage:**

```yaml
include:
  - project: 'Leathal1/TITO'
    file: '.gitlab/tito-scan.gitlab-ci.yml'
    ref: main

tito-threat-model:
  variables:
    TITO_MAESTRO: "true"
    TITO_MITRE: "true"
    TITO_SEMGREP: "true"
    TITO_3D: "true"
    TITO_FAIL_ON: "critical"
```

### MR Threat Diff (`.gitlab/tito-diff.gitlab-ci.yml`)

Compares threat models between the source and target branches of a merge request.

**Configuration variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `TITO_VERSION` | `latest` | TITO version to install |
| `TITO_FAIL_ON` | `critical` | Fail threshold |
| `TITO_FORMAT` | `markdown` | Output format (markdown, json, summary) |

**Usage:**

```yaml
include:
  - project: 'Leathal1/TITO'
    file: '.gitlab/tito-diff.gitlab-ci.yml'
    ref: main
```

**Exit codes:**
- `0` — PASS: No new threats or risk decreased
- `1` — WARN: New threats detected (non-critical, continues by default)
- `2` — FAIL: Critical security regression (blocks MR)

---

## Combined Pipeline

Use both templates together for comprehensive coverage:

```yaml
stages:
  - test
  - deploy

include:
  - project: 'Leathal1/TITO'
    file: '.gitlab/tito-scan.gitlab-ci.yml'
    ref: main
  - project: 'Leathal1/TITO'
    file: '.gitlab/tito-diff.gitlab-ci.yml'
    ref: main

# Full scan on default branch
tito-threat-model:
  variables:
    TITO_MAESTRO: "true"
    TITO_MITRE: "true"
  rules:
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'

# Diff on merge requests
tito-threat-diff:
  variables:
    TITO_FAIL_ON: "high"
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
```

## Docker-based Scanning

For faster execution without Go compilation:

```yaml
tito-scan:
  image: ghcr.io/leathal1/tito:latest
  stage: test
  script:
    - tito scan --repo . --maestro --mitre --attack-paths --output threat-model.html
  artifacts:
    paths:
      - threat-model.html
```

## Artifacts & Reports

TITO scan artifacts are automatically saved:
- `threat-model.html` — Interactive report (viewable via Pages or artifacts)
- `threatmodel.json` — Machine-readable scan data
- `threat-diff.md` — Markdown diff report (for MR comments)

### Publishing to GitLab Pages

```yaml
pages:
  stage: deploy
  needs: ["tito-threat-model"]
  script:
    - mkdir public
    - cp threat-model.html public/index.html
  artifacts:
    paths:
      - public
  rules:
    - if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH'
```

---

## Troubleshooting

### Semgrep installation fails
Set `TITO_SEMGREP: "false"` or add `pip install semgrep` to `before_script`.

### Git fetch errors in diff mode
Ensure your CI runner has access to fetch the target branch:
```yaml
variables:
  GIT_DEPTH: 0
```

### Rate limiting on go install
Use Docker image instead: `ghcr.io/leathal1/tito:latest`

---

_For GitHub Actions integration, see [action.yml](action.yml) and the [README](README.md)._
