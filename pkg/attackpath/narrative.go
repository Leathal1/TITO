package attackpath

import (
	"fmt"
	"strings"

	"github.com/Leathal1/TITO/pkg/dataflow"
)

// NarrativeGenerator generates human-readable attack stories
type NarrativeGenerator struct {
	graph *AttackGraph
}

// NewNarrativeGenerator creates a new narrative generator
func NewNarrativeGenerator(graph *AttackGraph) *NarrativeGenerator {
	return &NarrativeGenerator{graph: graph}
}

// GenerateNarrative creates a human-readable attack story for a path
func (ng *NarrativeGenerator) GenerateNarrative(path AttackPath) string {
	if len(path.Steps) == 0 {
		return "No attack path available."
	}

	var narrative strings.Builder

	// Introduction
	entryNode := ng.graph.Nodes[path.EntryPoint]
	targetNode := ng.graph.Nodes[path.Target]

	if entryNode == nil || targetNode == nil {
		return "Invalid attack path."
	}

	// Determine attacker skill level based on total difficulty
	attackerType := ng.getAttackerType(path.TotalDifficulty)
	
	narrative.WriteString(fmt.Sprintf("%s accesses the %s", 
		attackerType, 
		ng.formatNodeName(entryNode)))

	// Check if entry point is authenticated
	if entryNode.Zone == "internet" || entryNode.NodeType == dataflow.NodeExternal {
		narrative.WriteString(" (ENTRY POINT)")
	}

	// Describe findings at entry point
	if len(entryNode.Findings) > 0 {
		vulnerability := ng.getMostSevereVulnerability(entryNode.Findings)
		if vulnerability != "" {
			narrative.WriteString(fmt.Sprintf(", exploiting a %s vulnerability", vulnerability))
		}
	}

	narrative.WriteString(". ")

	// Describe each step
	for i, step := range path.Steps {
		toNode := ng.graph.Nodes[step.ToNode]
		if toNode == nil {
			continue
		}

		// Transition phrase
		if i > 0 {
			narrative.WriteString("Then, ")
		}

		// Describe the technique
		narrative.WriteString(fmt.Sprintf("the attacker %s to reach the %s",
			ng.getTechniqueVerb(step.Technique),
			ng.formatNodeName(toNode)))

		// Add MITRE technique if available
		if step.MitreID != "" {
			narrative.WriteString(fmt.Sprintf(" (%s)", step.MitreID))
		}

		// Describe difficulty
		if step.Difficulty > 0.7 {
			narrative.WriteString(" despite strong security controls")
		} else if step.Difficulty < 0.3 {
			narrative.WriteString(" with minimal effort")
		}

		narrative.WriteString(". ")
	}

	// Final impact statement
	narrative.WriteString(fmt.Sprintf("\n\nThe attacker gains access to the %s",
		ng.formatNodeName(targetNode)))

	// Describe what's at stake
	if targetNode.IsCrownJewel {
		impact := ng.describeImpact(targetNode)
		narrative.WriteString(fmt.Sprintf(", %s (CROWN JEWEL)", impact))
	}

	narrative.WriteString(".")

	// Summary statistics
	narrative.WriteString("\n\n📊 Attack Summary:")
	narrative.WriteString(fmt.Sprintf("\n   • Total Steps: %d", len(path.Steps)))
	narrative.WriteString(fmt.Sprintf("\n   • Attack Difficulty: %s", ng.getDifficultyLevel(path.TotalDifficulty)))
	
	boundariesCrossed := ng.countBoundariesCrossed(path.Steps)
	narrative.WriteString(fmt.Sprintf("\n   • Trust Boundaries Crossed: %d", boundariesCrossed))

	if len(path.MitreTactics) > 0 {
		narrative.WriteString(fmt.Sprintf("\n   • ATT&CK Tactics: %s", strings.Join(path.MitreTactics, " → ")))
	}

	narrative.WriteString(fmt.Sprintf("\n   • Composite Risk Score: %.1f/10.0 (%s)", 
		path.CompositeRisk, 
		GetRiskLevel(path.CompositeRisk)))

	return narrative.String()
}

// getAttackerType returns attacker description based on difficulty
func (ng *NarrativeGenerator) getAttackerType(difficulty float64) string {
	if difficulty < 0.1 {
		return "A script kiddie"
	} else if difficulty < 0.3 {
		return "An opportunistic attacker"
	} else if difficulty < 0.6 {
		return "A skilled attacker"
	}
	return "An advanced persistent threat (APT)"
}

// formatNodeName formats a node name for the narrative
func (ng *NarrativeGenerator) formatNodeName(node *AttackNode) string {
	return fmt.Sprintf("%s %s", node.NodeType, node.Label)
}

// getTechniqueVerb converts technique to a narrative verb
func (ng *NarrativeGenerator) getTechniqueVerb(technique string) string {
	techniqueLower := strings.ToLower(technique)
	
	if strings.Contains(techniqueLower, "injection") {
		return "exploits an injection vulnerability"
	} else if strings.Contains(techniqueLower, "api") {
		return "leverages the API connection"
	} else if strings.Contains(techniqueLower, "database") {
		return "uses the database connection"
	} else if strings.Contains(techniqueLower, "lateral") {
		return "moves laterally"
	} else if strings.Contains(techniqueLower, "rpc") {
		return "exploits the remote procedure call"
	}
	
	return "pivots"
}

// getMostSevereVulnerability gets the most severe finding description
func (ng *NarrativeGenerator) getMostSevereVulnerability(findings []dataflow.Finding) string {
	var mostSevere *dataflow.Finding
	maxScore := 0

	for i, finding := range findings {
		score := ng.getSeverityScore(finding.Severity)
		if score > maxScore {
			maxScore = score
			mostSevere = &findings[i]
		}
	}

	if mostSevere != nil {
		// Extract vulnerability type from title or STRIDE
		if mostSevere.Title != "" {
			return strings.ToLower(mostSevere.Title)
		}
		if mostSevere.STRIDE != "" {
			return fmt.Sprintf("%s", strings.ToLower(mostSevere.STRIDE))
		}
		return mostSevere.Severity + " severity"
	}

	return ""
}

// getSeverityScore converts severity to numeric score
func (ng *NarrativeGenerator) getSeverityScore(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// describeImpact describes what's at risk for a crown jewel
func (ng *NarrativeGenerator) describeImpact(node *AttackNode) string {
	labelLower := strings.ToLower(node.Label)

	if strings.Contains(labelLower, "user") || strings.Contains(labelLower, "customer") {
		return "potentially compromising user data and PII"
	} else if strings.Contains(labelLower, "payment") || strings.Contains(labelLower, "financial") {
		return "exposing financial and payment information"
	} else if strings.Contains(labelLower, "secret") || strings.Contains(labelLower, "credential") {
		return "obtaining sensitive credentials and secrets"
	} else if strings.Contains(labelLower, "admin") {
		return "gaining administrative control over the system"
	} else if node.NodeType == dataflow.NodeDatabase {
		return "obtaining full database access"
	}

	return "accessing critical system resources"
}

// getDifficultyLevel converts difficulty score to readable level
func (ng *NarrativeGenerator) getDifficultyLevel(difficulty float64) string {
	if difficulty < 0.1 {
		return "TRIVIAL"
	} else if difficulty < 0.3 {
		return "LOW"
	} else if difficulty < 0.6 {
		return "MEDIUM"
	} else if difficulty < 0.8 {
		return "HIGH"
	}
	return "VERY HIGH"
}

// countBoundariesCrossed counts trust boundary crossings
func (ng *NarrativeGenerator) countBoundariesCrossed(steps []AttackStep) int {
	count := 0
	prevZone := ""

	for _, step := range steps {
		fromNode := ng.graph.Nodes[step.FromNode]
		toNode := ng.graph.Nodes[step.ToNode]

		if fromNode != nil && toNode != nil {
			if prevZone == "" {
				prevZone = fromNode.Zone
			}

			if toNode.Zone != prevZone {
				count++
				prevZone = toNode.Zone
			}
		}
	}

	return count
}

// ExtractMitreTactics extracts ordered MITRE ATT&CK tactics from path
func ExtractMitreTactics(steps []AttackStep) []string {
	// Map common techniques to tactics
	tacticMap := map[string]string{
		"T1190": "Initial Access",
		"T1212": "Credential Access",
		"T1021": "Lateral Movement",
		"T1078": "Persistence",
		"T1098": "Persistence",
		"T1005": "Collection",
		"T1041": "Exfiltration",
		"T1071": "Command and Control",
	}

	tactics := make([]string, 0)
	seen := make(map[string]bool)

	// Initial Access is always first if entry point exists
	if len(steps) > 0 {
		tactics = append(tactics, "Initial Access")
		seen["Initial Access"] = true
	}

	// Extract tactics from MITRE IDs
	for _, step := range steps {
		if step.MitreID != "" {
			if tactic, exists := tacticMap[step.MitreID]; exists && !seen[tactic] {
				tactics = append(tactics, tactic)
				seen[tactic] = true
			}
		}
	}

	// Collection is likely if reaching a database
	if !seen["Collection"] {
		for _, step := range steps {
			if strings.Contains(strings.ToLower(step.Technique), "database") {
				tactics = append(tactics, "Collection")
				seen["Collection"] = true
				break
			}
		}
	}

	// Exfiltration is likely at the end
	if !seen["Exfiltration"] && len(steps) > 1 {
		tactics = append(tactics, "Exfiltration")
	}

	return tactics
}
