# ATIP Architecture

## Philosophy

ATIP is not another security dashboard. It's an **intelligence organism** designed to transform raw threat data into actionable clarity for defenders making critical decisions under pressure.

## Design Principles

### 1. Think Like an Adversary
Every threat represents intent to cause harm. ATIP maps adversarial tradecraft to defender mental models through the STRIDE-LM framework.

### 2. Signal Over Noise
Aggressive deduplication, intelligent scoring, and context-aware filtering ensure analysts see only what matters. Every alert that reaches a human deserves to reach a human.

### 3. Context is King
Raw indicators are useless without context. ATIP enriches every threat with:
- Asset relevance (affects YOUR stack?)
- Attack surface mapping
- Active exploitation status
- Historical patterns

### 4. Continuous Learning
Feedback loops are first-class citizens. Analyst actions train the scoring system. The system gets smarter with use.

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     ATIP ARCHITECTURE                       │
└─────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│  COLLECTION LAYER                                            │
├──────────────────────────────────────────────────────────────┤
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │   NVD    │  │  OSINT   │  │ Malware  │  │ Exploits │    │
│  │Collector │  │Collector │  │Collector │  │Collector │    │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘    │
│       │             │              │             │           │
│       └─────────────┴──────────────┴─────────────┘           │
│                             │                                │
└─────────────────────────────┼────────────────────────────────┘
                              ▼
┌──────────────────────────────────────────────────────────────┐
│  PROCESSING LAYER                                            │
├──────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Intelligence Pipeline                               │   │
│  │                                                       │   │
│  │  1. Normalize   → Ensure consistent format           │   │
│  │  2. Enrich      → Add context                        │   │
│  │  3. Deduplicate → Remove duplicates                  │   │
│  │  4. Prioritize  → Calculate scores                   │   │
│  │  5. Filter      → Remove noise                       │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────┬────────────────────────────────┘
                              ▼
┌──────────────────────────────────────────────────────────────┐
│  ANALYSIS LAYER                                              │
├──────────────────────────────────────────────────────────────┤
│  ┌──────────────────┐  ┌──────────────────┐                 │
│  │   STRIDE-LM      │  │  Prioritization  │                 │
│  │  Classification  │  │     Engine       │                 │
│  │                  │  │                  │                 │
│  │  • Spoofing      │  │  • Severity      │                 │
│  │  • Tampering     │  │  • Context       │                 │
│  │  • Repudiation   │  │  • Urgency       │                 │
│  │  • Info Disc.    │  │  • Recency       │                 │
│  │  • DoS           │  │                  │                 │
│  │  • Elevation     │  │  → Priority      │                 │
│  │  • Lateral Mov.  │  │    Score         │                 │
│  │  • Malware       │  │    (0.0-1.0)     │                 │
│  └──────────────────┘  └──────────────────┘                 │
└─────────────────────────────┬────────────────────────────────┘
                              ▼
┌──────────────────────────────────────────────────────────────┐
│  DISSEMINATION LAYER                                         │
├──────────────────────────────────────────────────────────────┤
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │   API    │  │ Reports  │  │  Alerts  │  │   CLI    │    │
│  │          │  │          │  │          │  │          │    │
│  │ REST/    │  │ Markdown │  │  Email   │  │ Commands │    │
│  │ GraphQL  │  │   JSON   │  │  Slack   │  │  Status  │    │
│  │          │  │   HTML   │  │ Webhook  │  │  Collect │    │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘    │
└──────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Collectors (`atip/collectors/`)

**Purpose:** Breathe in chaos from external sources.

**Design:**
- Abstract base class (`BaseCollector`) defines interface
- Concrete collectors implement specific sources
- Scheduled vs. streaming collectors
- Error handling and retry logic
- Rate limiting and API key management

**Key Files:**
- `base.py` - Base collector interface
- `cve/nvd_collector.py` - NVD CVE collector
- `osint/osint_collector.py` - OSINT feeds collector

### 2. STRIDE-LM Engine (`atip/core/stride_lm/`)

**Purpose:** The lens through which all threats are viewed.

**Design:**
- Extended STRIDE framework with Lateral Movement and Malware
- Multi-signal classification (keywords, CWE, MITRE ATT&CK)
- Confidence scores for each category
- Primary + secondary category assignment
- Detection and mitigation strategy mapping

**Key Files:**
- `categories.py` - STRIDE-LM category definitions
- `classifier.py` - Classification engine

**Classification Signals:**
1. **Keyword matching (40%)** - Pattern matching in threat description
2. **CWE mapping (30%)** - Authoritative weakness classification
3. **MITRE ATT&CK (20%)** - Tactic/technique mapping
4. **Context heuristics (10%)** - Additional contextual signals

### 3. Data Models (`atip/core/models/`)

**Purpose:** Intelligence, not data.

**Key Concepts:**
- `Threat` - Primary intelligence object
- `ThreatIndicator` - Atomic indicators (CVE, IP, hash, etc.)
- `ThreatContext` - What makes data intelligence
- `StrideLMProfile` - Multi-dimensional classification

**Priority Calculation:**
```python
priority = (
    0.3 * severity_score +    # Base severity
    0.4 * urgency_score +     # Exploitation + exposure
    0.2 * stride_score +      # Classification confidence
    0.1 * recency_score       # Temporal relevance
)
```

### 4. Processing Pipeline (`atip/core/pipeline/`)

**Purpose:** Transform raw threats into refined intelligence.

**Stages:**
1. **Normalize** - Consistent formatting, fill defaults
2. **Enrich** - Add context (assets, exploitation, campaigns)
3. **Deduplicate** - Remove duplicate threats (by CVE, IOC, title)
4. **Prioritize** - Calculate priority scores
5. **Filter** - Remove low-quality threats

**Deduplication Strategy:**
- CVEs: dedupe by CVE ID
- IOCs: dedupe by indicator value
- Others: dedupe by title similarity
- On duplicate: merge into existing with updated info

### 5. Dissemination (`atip/dissemination/`)

**Purpose:** Deliver intelligence in usable formats.

**Channels:**
- **Reports** - Markdown, JSON, HTML reports for humans
- **API** - REST/GraphQL for programmatic access
- **Alerts** - Real-time notifications (email, Slack, webhooks)
- **CLI** - Command-line interface for operators

### 6. Configuration (`atip/config/`)

**Purpose:** Sensible defaults, progressive disclosure.

**Features:**
- YAML configuration files
- Environment variable overrides
- Hierarchical config with dot notation
- Config validation

## Data Flow

### Threat Intelligence Lifecycle

```
1. COLLECTION
   ↓
   Raw threat data from sources
   ↓
2. PROCESSING
   ↓
   Normalized, enriched threat objects
   ↓
3. ANALYSIS
   ↓
   STRIDE-LM classification + prioritization
   ↓
4. DISSEMINATION
   ↓
   Reports, alerts, API responses
   ↓
5. FEEDBACK
   ↓
   Analyst actions → system tuning
```

### Example Flow: CVE Processing

```python
# 1. Collection
nvd_collector = NVDCollector()
raw_threats = nvd_collector.collect()
# → Fetches CVEs from NVD API
# → Parses into Threat objects

# 2. Processing
pipeline = ThreatPipeline()
processed = pipeline.process(raw_threats)
# → Normalizes data
# → Enriches with context
# → Deduplicates
# → Filters noise

# 3. Analysis (automatic in pipeline)
# → STRIDE-LM classification
# → Priority scoring

# 4. Dissemination
report_gen = MarkdownReportGenerator()
report_gen.generate(processed)
# → Generates human-readable report
```

## Extension Points

### Adding a New Collector

1. Inherit from `BaseCollector` or `ScheduledCollector`
2. Implement `source_name`, `fetch()`, `parse()`
3. Register in configuration
4. Add to CLI

```python
class MyCollector(ScheduledCollector):
    @property
    def source_name(self) -> str:
        return "MySource"

    @property
    def interval_seconds(self) -> int:
        return 3600  # 1 hour

    def fetch(self) -> List[Dict]:
        # Fetch raw data
        pass

    def parse(self, raw_data: Dict) -> Optional[Threat]:
        # Transform into Threat
        pass
```

### Adding a New Report Format

1. Create generator in `atip/dissemination/reports/`
2. Implement `generate(threats: List[Threat])`
3. Add to CLI options

### Customizing Classification

1. Extend `CATEGORY_PATTERNS` in `stride_lm/categories.py`
2. Override `_score_context()` in classifier
3. Add custom heuristics

## Performance Considerations

### Scalability

- **Current**: Single-process, suitable for small-medium deployments
- **Future**:
  - Async I/O for collectors
  - Message queue for pipeline
  - Distributed processing
  - Caching layer (Redis)

### Optimization Targets

1. **Collector efficiency**: Rate limiting, pagination, caching
2. **Pipeline throughput**: Batch processing, parallel enrichment
3. **Deduplication**: Bloom filters for large datasets
4. **Storage**: PostgreSQL for production, SQLite for dev

## Security Considerations

### Input Validation
- Sanitize all external data
- Validate schemas
- Rate limit API endpoints

### Secret Management
- API keys in env vars or secret manager
- No secrets in config files
- Rotate keys regularly

### Access Control
- API authentication required
- Role-based access control
- Audit logging

## Future Enhancements

### Short Term
- [ ] API server implementation (FastAPI)
- [ ] Database persistence (SQLAlchemy)
- [ ] Additional collectors (AlienVault OTX, VirusTotal)
- [ ] Webhook alerting

### Medium Term
- [ ] Asset inventory integration
- [ ] ML-based threat scoring
- [ ] Threat hunting workflows
- [ ] SOAR integration

### Long Term
- [ ] Distributed architecture
- [ ] Real-time streaming pipeline
- [ ] Advanced correlation engine
- [ ] Custom playbook execution

---

*"The best defense is built by those who truly understand offense."*
