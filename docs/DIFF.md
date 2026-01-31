# TITO Diff - PR Threat Model Delta

The #2 most important feature for TITO — the DevSecOps adoption engine.

## Overview

`tito diff` compares threat models between two scan results and outputs what changed: new attack surface, resolved threats, shifted risk scores. Designed to run in CI on every pull request.

**Think:** Security regression testing for every code change.

## Quick Start

### Compare Two Saved Scans

```bash
# Scan main branch
tito scan --repo . --branch main --save main.tito.json

# Scan feature branch
tito scan --repo . --branch feature --save feature.tito.json

# Compare
tito diff --before main.tito.json --after feature.tito.json
```

### Compare Branches Automatically

```bash
# Scans both branches automatically
tito diff --repo https://github.com/user/repo --base main --head feature-branch
```

## Usage

### Basic Commands

```bash
# File comparison mode
tito diff --before base.tito.json --after head.tito.json

# Branch comparison mode
tito diff --repo . --base main --head feature-branch

# Different output formats
tito diff --before base.tito.json --after head.tito.json --format markdown
tito diff --before base.tito.json --after head.tito.json --format json
tito diff --before base.tito.json --after head.tito.json --format summary

# Write to file
tito diff --before base.tito.json --after head.tito.json --output diff-report.md

# Save intermediate scan results
tito diff --repo . --base main --head feature --save pr-scan.tito.json
```

### Fail-On Modes

Control when the diff command exits non-zero (for CI integration):

```bash
# Fail on critical threats only (default)
tito diff --before base.tito.json --after head.tito.json --fail-on critical

# Fail on high+ severity threats
tito diff --before base.tito.json --after head.tito.json --fail-on high

# Fail on any new threat
tito diff --before base.tito.json --after head.tito.json --fail-on any

# Never fail (always exit 0)
tito diff --before base.tito.json --after head.tito.json --fail-on never
```

### Exit Codes

- **0** = PASS: No new threats or risk decreased
- **1** = WARN: New threats detected (non-critical)
- **2** = FAIL: Critical security regression

## Output Formats

### Markdown (Default)

GitHub-friendly markdown with emoji, tables, and PR-ready formatting:

```markdown
## 🛡️ TITO Threat Model Delta

**Risk: ⬆️ INCREASED** (6.2 → 7.8) | Verdict: ⚠️ WARN

### Changes
| Category | Added | Removed | Modified |
|----------|-------|---------|----------|
| Assets | +3 | -1 | 2 |
| Threats | +2 | 0 | - |
...

### ⚠️ New Threats (2)
- 🔴 **SQL Injection in /api/users** [CRITICAL] — New unauthenticated API endpoint
...
```

### JSON

Machine-readable JSON for tooling integration:

```json
{
  "base": { "version": "1.0", ... },
  "head": { "version": "1.0", ... },
  "addedAssets": [...],
  "addedThreats": [...],
  "riskDelta": {
    "baseMaxRisk": 6.2,
    "headMaxRisk": 7.8,
    "riskDirection": "increased"
  },
  "summary": {
    "riskVerdict": "WARN",
    "verdictReason": "+2 new high-severity threats"
  }
}
```

### Summary

One-line summary for CI logs:

```
⚠️ WARN: +2 new high-severity threat(s). Risk increased 6.2 → 7.8
```

## CI Integration

### GitHub Actions

Use the included workflow template:

```yaml
# .github/workflows/tito-pr-check.yml
name: TITO Threat Model Check
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
      
      - name: Run Threat Diff
        run: |
          tito diff \
            --repo . \
            --base ${{ github.base_ref }} \
            --head ${{ github.head_ref }} \
            --format markdown \
            --output threat-diff.md \
            --fail-on critical
      
      - name: Comment on PR
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
```

### GitLab CI

```yaml
threat-diff:
  stage: security
  script:
    - go install github.com/Leathal1/TITO/cmd/tito@latest
    - tito diff --repo . --base main --head $CI_COMMIT_REF_NAME --format markdown
  only:
    - merge_requests
```

### Jenkins

```groovy
stage('Threat Model Diff') {
  steps {
    sh '''
      go install github.com/Leathal1/TITO/cmd/tito@latest
      tito diff --repo . --base main --head ${BRANCH_NAME} --fail-on critical
    '''
  }
}
```

## What Gets Compared

### Assets
- **Added**: New API endpoints, databases, secrets, file operations
- **Removed**: Deleted components
- **Modified**: Changed exposure (internal → public), sensitivity flags

### Threats
- **Added**: New vulnerabilities, attack vectors
- **Removed**: Resolved/mitigated threats

### Data Flows
- **Added**: New data paths (e.g., API → Database)
- **Removed**: Deleted flows

### Attack Paths
- **Added**: New multi-step attack chains
- **Removed**: Broken attack paths

### Dependencies
- **Added**: New libraries
- **Removed**: Deleted dependencies
- **Updated**: Version changes

### Risk Metrics
- **Max Risk**: Highest risk score (0-10 scale)
- **Avg Risk**: Average risk across all threats
- **Direction**: Increased, decreased, or unchanged

## Verdict Logic

The verdict is determined by:

1. **FAIL** if:
   - New critical threats (default)
   - New high-severity threats (with `--fail-on high`)
   - Risk increased significantly
   - Max risk exceeds threshold

2. **WARN** if:
   - New high-severity threats (with `--fail-on critical`)
   - Risk increased slightly
   - New attack paths

3. **PASS** if:
   - No new threats
   - Threats resolved
   - Risk decreased or stable

## Advanced Usage

### Custom Verdict Thresholds

Edit config.yaml to customize verdict behavior:

```yaml
diff:
  failOnCritical: true
  failOnHigh: false
  warnOnHigh: true
  maxRiskThreshold: 0.8
  riskIncreasePercent: 0.2  # 20% increase triggers fail
```

### Pre-commit Hook

Add to `.git/hooks/pre-push`:

```bash
#!/bin/bash
# Scan current branch
tito scan --repo . --save /tmp/current.tito.json

# Compare with main
git fetch origin main
tito diff --repo . --base origin/main --head HEAD --format summary

# Exit with diff result
exit $?
```

### Baseline Management

```bash
# Create baseline from main branch
tito scan --repo . --branch main --save baselines/main.tito.json

# Compare PRs against stable baseline
tito diff --before baselines/main.tito.json --after current.tito.json
```

## Best Practices

1. **Run on every PR** - Catch security regressions early
2. **Use `--fail-on critical`** - Don't block PRs for minor issues
3. **Review WARN verdicts** - New high-severity threats deserve attention
4. **Save baselines** - Keep scan results for trending
5. **Comment on PRs** - Make findings visible to developers
6. **Combine with gates** - Require manual approval for FAIL verdicts

## Troubleshooting

### "No changes detected" on identical code

Make sure you're comparing the same commit/branch. Use `--save` to preserve exact scan results.

### Exit code always 0

Check `--fail-on` setting. Use `--fail-on critical` or `--fail-on high`.

### Missing threats in diff

Ensure both scans ran with the same flags (e.g., both with `--semgrep` or both without).

### Large diffs from minor changes

Normal! Small code changes can expose new attack surface. Review carefully.

## Examples

### Example 1: New API Endpoint

```markdown
### ⚠️ New Threats (1)
- 🔴 **SQL Injection in /api/admin/users** [CRITICAL]
  — New unauthenticated endpoint with database access

### 📊 New Assets (1)
- `api` POST /api/admin/users (routes.go:45) — **exposed, sensitive**
```

**Action**: Add authentication middleware before merging.

### Example 2: Dependency Update

```markdown
### 📦 Updated Dependencies (1)
- express: 4.17.0 → 4.18.2

### ✅ Resolved Threats (3)
- CVE-2022-24999 [HIGH]
- Path Traversal in express [MEDIUM]
- ReDoS vulnerability [LOW]
```

**Action**: Merge with confidence.

### Example 3: Refactoring

```markdown
### 🔄 Modified Assets (2)
- `api` GET /api/internal/data: exposure changed: true → false
- `database` User Query: sensitivity changed: false → true

**Risk: ⬇️ DECREASED** (7.2 → 5.8) | Verdict: ✅ PASS
```

**Action**: Great refactoring! Ship it.

## Future Enhancements

- [ ] Trend analysis (risk over time)
- [ ] Policy-as-code (custom verdict rules)
- [ ] Integration with ticketing systems (auto-create Jira tickets)
- [ ] Slack/Teams notifications
- [ ] Diff visualization (before/after diagrams)
- [ ] Historical comparison (compare with 30 days ago)

## Support

- **Docs**: https://github.com/Leathal1/TITO
- **Issues**: https://github.com/Leathal1/TITO/issues
- **CI Examples**: `.github/workflows/tito-pr-check.yml`
