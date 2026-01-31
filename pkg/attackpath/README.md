# Attack Path Analysis Package

The `attackpath` package provides kill chain visualization for TITO, answering the question: **"If an attacker lands here, what's the worst-case path to crown jewels?"**

Think BloodHound but for application-layer threat models.

## Features

- **Attack Graph Construction**: Converts data flow diagrams into attack graphs with entry points and crown jewels
- **Path Finding**: Multiple algorithms (BFS, DFS, Dijkstra) to find realistic attack paths
- **Risk Scoring**: Composite risk scores based on exploitability, crown jewel value, and attack difficulty
- **Narrative Generation**: Template-based human-readable attack stories (no LLM required)
- **3D Visualization**: Interactive Three.js visualization with animated attack path overlays

## Architecture

### Core Types (`types.go`)

- **AttackGraph**: Complete attack graph with nodes, edges, entry points, and crown jewels
- **AttackNode**: Wraps dataflow nodes with attack-relevant metadata (exploitability, zone, etc.)
- **AttackEdge**: Represents lateral movement with difficulty scoring
- **AttackPath**: Complete attack chain from entry to target with risk score and narrative

### Graph Builder (`graph.go`)

Converts `DiagramData` into `AttackGraph`:

- Maps trust boundary zones to nodes
- Identifies entry points (internet zone, external/API nodes, exposed endpoints)
- Identifies crown jewels (databases, critical risk nodes, sensitive data stores)
- Calculates exploitability from findings
- Calculates edge difficulty from encryption, trust boundaries, sensitivity

### Path Finder (`pathfinder.go`)

Graph traversal algorithms:

- `FindAllPaths(maxDepth)`: DFS with cycle detection and depth limiting
- `FindShortestPaths()`: Dijkstra using difficulty as weight (easiest path for attacker)
- `FindCriticalPaths(topN)`: Returns N most dangerous paths by risk score

### Scorer (`scorer.go`)

Composite risk scoring (0.0-10.0):

- **Base**: Attacker's probability of success (product of `1 - difficulty` for each step)
- **Crown jewel value**: Based on risk level, node type, findings
- **Entry point exposure**: Internet-facing = higher risk
- **Trust boundaries crossed**: More boundaries = higher risk
- **ATT&CK techniques**: Known techniques = higher risk

### Narrative Generator (`narrative.go`)

Template-based attack story generation:

- Attacker skill level (script kiddie → APT based on difficulty)
- Step-by-step attack progression
- Impact description
- Attack summary with stats

## Usage

### CLI

#### Dedicated Attack Path Analysis

```bash
tito attack-paths --repo https://github.com/user/repo
tito attack-paths --repo . --top 5 --3d --narrative
```

#### Integrated with Scan

```bash
tito scan --repo . --3d --attack-paths
```

### Programmatic

```go
import (
    "github.com/Leathal1/TITO/pkg/attackpath"
    "github.com/Leathal1/TITO/pkg/dataflow"
)

// Build attack graph
builder := attackpath.NewGraphBuilder(diagramData)
graph := builder.Build()

// Find critical paths
finder := attackpath.NewPathFinder(graph)
paths := finder.FindCriticalPaths(5)

// Score and generate narratives
scorer := attackpath.NewScorer(graph)
narrativeGen := attackpath.NewNarrativeGenerator(graph)

for i := range paths {
    paths[i].CompositeRisk = scorer.ScorePath(paths[i].Steps)
    paths[i].MitreTactics = attackpath.ExtractMitreTactics(paths[i].Steps)
    paths[i].Narrative = narrativeGen.GenerateNarrative(paths[i])
}

// Generate 3D visualization with attack paths
generator3D := dataflow.NewGenerator3D()
generator3D.Generate3DWithAttackPaths(diagramData, paths, "output.html")
```

## 3D Visualization

The 3D visualization includes:

- **Attack Paths Panel**: Sidebar with ranked paths
- **Node Highlighting**: 
  - Green ring: Entry points
  - Red glow: Crown jewels
  - Red highlight: Active path nodes
- **Edge Highlighting**: Thick red lines with animated particles
- **Interactive Selection**: Click paths to visualize
- **Risk Badges**: Color-coded risk levels (🔴 Critical, 🟠 High, 🟡 Medium, 🟢 Low)

## Example Output

```
⚔️  TITO Attack Path Analysis
==================================================

📍 Entry Points: 3 (API Gateway, Web Frontend, Webhook Handler)
🏆 Crown Jewels: 2 (Users Database, Secrets Vault)

🔴 Critical Path #1 (Risk: 9.2/10)
   API Gateway → Backend Service → Users Database
   Steps: 2 | Difficulty: LOW | Boundaries Crossed: 1
   ATT&CK Chain: Initial Access → Execution → Collection → Exfiltration
   
   Narrative: A skilled attacker accesses the api API Gateway (ENTRY POINT), 
   exploiting a SQL injection vulnerability (T1190). Then, the attacker uses 
   the database connection to reach the database Users Database. The attacker 
   gains access to the database Users Database, obtaining full database access 
   (CROWN JEWEL).
```

## Testing

Run tests:

```bash
go test ./pkg/attackpath/...
```

Tests cover:
- Graph building from DiagramData
- Entry point and crown jewel detection
- Path finding with various topologies (linear, diamond, star, cyclic)
- Risk scoring
- Narrative generation
- Cycle detection

Current coverage: 85%+

## Implementation Details

### Entry Point Detection

A node is an entry point if:
- In "internet" zone
- Type is External or User
- Type is API (gateway pattern)
- No incoming edges from internal zones

### Crown Jewel Detection

A node is a crown jewel if:
- Type is Database
- RiskLevel is Critical
- Has sensitive data flows (incoming or outgoing)
- Label contains keywords: secret, credential, password, key, vault, admin

### Difficulty Calculation

Edge difficulty (0.0-1.0, higher = harder for attacker):

- Base: 0.3
- +0.3 if encrypted
- +0.2 if crosses trust boundary
- -0.1 if sensitive data (attractive target)

### Risk Scoring

Path composite risk (0.0-10.0):

```
risk = (success_probability * 4.0) +
       (crown_jewel_value * 3.0) +
       (exposure_score * 1.0) +
       (boundary_penalty * 1.0) +
       (attack_bonus * 1.0)
```

## Future Enhancements

- [ ] Custom crown jewel filtering by type/name
- [ ] Attack path comparison and similarity analysis
- [ ] Time-based attack progression simulation
- [ ] Defense recommendations per path
- [ ] Export to MITRE ATT&CK Navigator
- [ ] Integration with actual exploit databases
- [ ] Machine learning for difficulty prediction

## License

Part of TITO - Advanced Threat Intelligence Platform
