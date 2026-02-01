# TITO Roadmap

*Threat In, Threat Out — The open-source threat modeling standard*

---

## ✅ Shipped (v2.x — Current)

- [x] STRIDE-LM threat classification
- [x] MAESTRO agentic AI analysis
- [x] MITRE ATT&CK technique mapping
- [x] PCI DSS v4.0 compliance mapping & gap analysis
- [x] Application architecture detection (11 types)
- [x] Architecture-aware threat adjustments
- [x] Semgrep-powered code analysis
- [x] Attack path analysis with narratives
- [x] PR threat model diffing
- [x] Interactive 2D & 3D data flow visualization
- [x] Custom PCI Semgrep rule packs
- [x] Threat consolidation & category-based summaries

---

## 🔨 Phase 1: Foundation (Q1 2026)

### Drift Detection (CI/CD Integration)
- [ ] `tito ci` command — optimized for pipeline use
- [ ] Baseline threat model generation & storage (`.tito/baseline.json`)
- [ ] PR-level diff: "This PR introduces 3 new attack paths"
- [ ] GitHub Action with inline PR comments
- [ ] GitLab CI template
- [ ] Exit codes for pipeline gating (fail on critical threats)
- [ ] SARIF output for GitHub Security tab integration

### OWASP Integration
- [ ] OWASP Top 10 mapping
- [ ] OWASP ASVS verification levels
- [ ] OWASP SAMM maturity mapping

### Additional Compliance Frameworks
- [ ] HIPAA compliance mapping
- [ ] SOC 2 Type II mapping
- [ ] ISO 27001 mapping
- [ ] NIST 800-53 mapping

---

## 🚀 Phase 2: Intelligence (Q2 2026)

### Auto-Remediation
- [ ] Generate fix suggestions for each threat
- [ ] PR-ready code patches with security explanations
- [ ] Framework-specific fix templates (Go, Python, JS, Java)
- [ ] `tito fix --threat <id>` interactive remediation

### LLM-Powered Executive Summaries
- [ ] Natural language threat report generation
- [ ] Non-technical executive summary output
- [ ] Risk prioritization narratives
- [ ] "What should we fix first and why" recommendations
- [ ] Configurable LLM backend (OpenAI, Anthropic, local models)

### SBOM → Threat Model
- [ ] Ingest CycloneDX & SPDX SBOMs
- [ ] Map every dependency to known threat patterns
- [ ] Supply chain risk scoring
- [ ] Transitive dependency attack path analysis

---

## 🏢 Phase 3: Scale (Q3-Q4 2026)

### Multi-Repo Organization Analysis
- [ ] Scan entire GitHub/GitLab orgs
- [ ] Cross-service attack path mapping
- [ ] Service dependency graph with trust boundaries
- [ ] Organization-wide threat posture dashboard
- [ ] "Service A trusts Service B which has SQLi" cross-repo findings

### Team & Enterprise Features
- [ ] Team workspaces with role-based access
- [ ] Scan history & trend tracking
- [ ] Scheduled scans with alerts
- [ ] Slack/Teams/Discord notifications
- [ ] API access for custom integrations
- [ ] SSO/SAML authentication

---

## 💰 Monetization Strategy

### Free & Open Source (Forever)
The CLI and all current features remain fully open source:
- STRIDE-LM, MAESTRO, MITRE ATT&CK, PCI DSS
- Architecture detection & threat adjustments
- Attack paths, Semgrep analysis, visualizations
- Single-repo scanning, PR diffing
- OWASP & additional compliance frameworks

### Premium Rule Packs (Gumroad — Available Now)
Continuously updated Semgrep rule packs for specialized scanning:
- **PCI DSS Rule Pack** — $29/mo
- **HIPAA Rule Pack** — $29/mo
- **SOC 2 Rule Pack** — $29/mo
- **AI Security Rule Pack** — $29/mo
- **Full Compliance Bundle** — $79/mo

Updated monthly with new CVE patterns, false positive tuning, and framework-specific rules.

### TITO Pro (Future — When Community is Ready)
Advanced features for teams and enterprises:
- CI/CD drift detection with pipeline gating
- Auto-remediation with PR-ready patches
- LLM-powered executive summaries
- SBOM threat model generation
- Multi-repo organization analysis
- Team workspaces & dashboards

---

## 🤝 Partnerships

- **CSA (Cloud Security Alliance)** — MAESTRO reference implementation listing
- **Semgrep** — Integration partnership, "Semgrep as an engine" listing
- **CrowdStrike** — Marketplace integration (in progress)
- **CISA** — Government adoption conversations

---

## 🗓 Launch Timeline

| Date | Milestone |
|------|-----------|
| Jan 31, 2026 | PCI DSS + Architecture Detection + Open Source Everything |
| Feb 3, 2026 | Ken Huang / CSA email + Semgrep docs PR |
| Feb 4, 2026 | Show HN launch |
| Feb 7, 2026 | r/netsec post |
| Feb 2026 | Gumroad rule packs live |
| Mar 2026 | CI/CD drift detection shipped |
| Q2 2026 | Auto-remediation + LLM summaries |
| Q3 2026 | Multi-repo + team features |

---

*Built by Steven Leath. Contributions welcome.*
*GitHub: https://github.com/Leathal1/TITO*
