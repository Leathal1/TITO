# TITO — Go-To-Market Plan

## Positioning
**"The only threat modeling tool that combines STRIDE-LM, MAESTRO agentic AI analysis, Semgrep SAST, and MITRE ATT&CK in a single binary."**

## Three Angles

| Audience | Message | Pain Point |
|----------|---------|------------|
| **AppSec teams** | "Threat modeling that integrates your SAST findings with STRIDE classification and ATT&CK technique mapping" | Manual threat models rot, SAST findings lack context |
| **AI/ML teams** | "MAESTRO threat modeling for agentic AI — prompt injection is just Layer 1 of 7" | No tools model agent-specific threats |
| **Compliance teams** | "Auto-generated, living threat documentation for SOC2/ISO27001" | Manual threat model docs are always stale |

## Pricing

**Everything is open source and free.** All features — STRIDE-LM, MAESTRO, MITRE ATT&CK, Semgrep integration, D3.js diagrams, 3D visualization, GitHub Action — ship in the single binary. No license keys, no feature gates.

**Monetization: Gumroad Rule Packs ($29/mo)**

| Product | Price | What You Get |
|---------|-------|--------------|
| **TITO CLI** | Free (open source) | Full-featured threat modeling binary — all features included |
| **Premium Rule Pack** | $29/mo | Curated STRIDE-LM + MAESTRO rules, updated monthly, covering emerging threats |
| **Playbook** | $29 one-time | STRIDE-LM + MAESTRO methodology guide |
| **Template Kit** | $19 one-time | D3.js diagram templates for custom visualizations |

## 4-Week Launch Calendar

### Week 1: Foundation (GitHub + HN + Reddit)
- [ ] Polish README with screenshots/GIFs of D3.js diagrams
- [ ] Add GitHub topics: `threat-modeling`, `stride`, `maestro`, `appsec`, `mitre-attack`, `semgrep`, `security`, `golang`
- [ ] Create GitHub Discussion: "What repos should we threat-model?"
- [ ] Tag a release v2.1.0 with cross-platform binaries + checksums
- [ ] **Show HN** post (Tuesday-Thursday, 9-11am ET):
  > Show HN: TITO – single binary threat modeling with STRIDE + MAESTRO for AI agents
  > Point at a repo, get a visual threat model. STRIDE-LM for traditional threats,
  > MAESTRO (CSA's 7-layer framework) for agentic AI, Semgrep SAST integration,
  > MITRE ATT&CK enrichment. Interactive D3.js data flow diagrams.
  > Single Go binary, zero deps. https://github.com/Leathal1/TITO
- [ ] **Reddit** posts:
  - r/netsec (Friday): Technical deep-dive on MAESTRO integration
  - r/cybersecurity: "We built an open-source threat modeling CLI"
  - r/golang: "219K LOC Go project: building TITO, a threat modeling platform"
  - r/devops: "Automated threat modeling in CI/CD with TITO"

### Week 2: Thought Leadership (Twitter + LinkedIn + Blog)
- [ ] **Twitter/X thread** (7-10 tweets):
  1. "We open-sourced TITO: threat modeling that actually covers AI agents 🛡️"
  2. Explain STRIDE-LM vs traditional STRIDE
  3. MAESTRO's 7 layers visualized
  4. Screenshot of D3.js data flow diagram
  5. "Here's what TITO found scanning itself" (eat your own dogfood)
  6. Semgrep + MITRE integration walkthrough
  7. Link to repo + pricing
  - Tags: #appsec #threatmodeling #agenticAI #cybersecurity #golang #devsecops
  - Tag: @AdamShoworthy (threat modeling author), @CloudSecAllianc, @semaborma
- [ ] **LinkedIn post**: Professional angle targeting CISOs and AppSec managers
  - "IriusRisk and ThreatModeler just merged. Here's what that means for teams under $30K/yr."
  - Position TITO as the alternative
- [ ] **Blog post** (dev.to + Hashnode):
  - "Why STRIDE Isn't Enough for AI Agents: Introducing MAESTRO Threat Modeling"
  - Include D3.js diagram screenshots
  - Link to GitHub + pricing

### Week 3: Products (Product Hunt + Gumroad + YouTube)
- [ ] **Product Hunt launch**:
  - Title: "TITO - Threat model any repo with one command"
  - Tagline: "STRIDE + MAESTRO + Semgrep + MITRE ATT&CK in a single Go binary"
  - Maker comment explaining the story
  - Schedule for Tuesday 12:01am PT
- [ ] **Gumroad listings**:
  - Premium Rule Pack ($29/mo) — curated STRIDE-LM + MAESTRO rules
  - STRIDE-LM + MAESTRO Playbook ($29) — write the content
  - D3.js Template Kit ($19) — package the templates
- [ ] **YouTube demo** (2-3 min):
  - Terminal: `tito scan --repo https://github.com/langchain-ai/langchain --maestro --dataflow`
  - Show the D3.js diagram output
  - Show the 3D visualization
  - "This is what a MAESTRO threat model looks like"
  - End with pricing CTA

### Week 4: Depth (Follow-up content + Conference CFPs)
- [ ] **Blog**: "MAESTRO Threat Modeling for MCP Servers: A Practical Guide"
  - Scan the OpenClaw/Moltbot codebase
  - Walk through the MAESTRO findings layer by layer
  - Show how tool poisoning (Layer 4) maps to MITRE T1555
- [ ] **Conference CFPs** (submit to all):
  - BSides (any city) — "Threat Modeling Agentic AI with MAESTRO"
  - OWASP Global — "Beyond STRIDE: MAESTRO for the Agent Internet"
  - DEF CON AI Village — "TITO: Automated Threat Intelligence for AI Systems"
  - Black Hat Arsenal — tool demo submission
  - CloudSecNext — "CSA MAESTRO in Practice: Scanning Real Agent Codebases"
- [ ] **Moltbook** ongoing engagement (security submolt)
- [ ] Follow up on any HN/Reddit/Twitter engagement

## Ongoing (Monthly)

- **Content**: 1 blog post/month on specific threat modeling topics
- **Moltbook**: Weekly engagement in m/security
- **GitHub**: Respond to issues within 24h, accept PRs, release monthly
- **Metrics to track**: GitHub stars, Gumroad sales, GitHub Action installs, newsletter subscribers

## Show HN Post (Ready to Go)

```
Show HN: TITO – Threat model any repo with one command

I built an open-source threat modeling tool that does something no other tool combines:

- STRIDE-LM (extended STRIDE with Lateral Movement + Malware)
- MAESTRO (CSA's 7-layer framework for agentic AI security)
- Semgrep SAST integration (auto-maps findings to threat categories)
- MITRE ATT&CK enrichment (every finding gets technique IDs)
- Interactive D3.js data flow diagrams (dark theme, conference-quality)

Single Go binary. Zero dependencies. Point at a repo, get a full threat model.

Quick start:
  go install github.com/Leathal1/TITO/cmd/tito@latest
  tito scan --repo . --maestro --semgrep --mitre --dataflow --output threat-model.html

Why I built this: I'm an AppSec engineer. Every threat modeling tool is either
free-but-basic (Microsoft TMT, Threat Dragon) or enterprise-but-$30K+ (IriusRisk).
Nothing in between. And none of them model agentic AI threats — which is the fastest
growing attack surface in our industry.

MAESTRO specifically models: prompt injection, RAG poisoning, MCP tool attacks,
agent-to-agent trust exploitation, sandbox escapes, and governance gaps.

100% open source. Every feature included. No license keys.
Premium rule packs on Gumroad ($29/mo) for curated emerging threat rules.

https://github.com/Leathal1/TITO
```

## Pricing Page Copy (for tito.security)

### TITO — Free & Open Source
**Every feature. No gates. No license keys.**
- STRIDE-LM + MAESTRO threat classification
- MITRE ATT&CK technique enrichment
- Semgrep SAST integration
- Interactive D3.js data flow diagrams + 3D visualization
- GitHub Action for CI/CD
- CLI with unlimited scans
- Community support (GitHub Issues)

[Download Free →]

### Premium Rule Pack — $29/mo
**Curated threat rules, updated monthly**
- Emerging threat patterns for STRIDE-LM + MAESTRO
- Industry-specific rule sets
- Priority Semgrep rulesets
- Monthly updates covering new CVEs and attack techniques

[Subscribe on Gumroad →]

### FAQ

**Is TITO really free?**
Yes. Every feature ships in the open source binary. No license keys, no feature gates, forever.

**What do rule packs add?**
The CLI includes comprehensive built-in rules. Premium rule packs add curated, frequently-updated rules targeting emerging threats and industry-specific patterns.

**Do you sell to competitors?**
TITO is open source (MIT). You can build on it freely.

**What about Semgrep's license?**
TITO calls Semgrep as a subprocess — you bring your own Semgrep installation. We don't bundle or redistribute Semgrep's rules.
