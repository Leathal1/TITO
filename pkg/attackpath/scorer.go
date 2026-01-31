package attackpath

import (
	"sort"
	"strings"

	"github.com/Leathal1/TITO/pkg/dataflow"
)

// Scorer calculates risk scores for attack paths
type Scorer struct {
	graph *AttackGraph
}

// NewScorer creates a new path scorer
func NewScorer(graph *AttackGraph) *Scorer {
	return &Scorer{graph: graph}
}

// ScorePath calculates composite risk score (0.0-10.0) for a path
func (s *Scorer) ScorePath(steps []AttackStep) float64 {
	if len(steps) == 0 {
		return 0.0
	}

	// Base score: attacker's probability of success
	// Calculate as product of (1 - difficulty) for each step
	successProbability := 1.0
	for _, step := range steps {
		// Lower difficulty = higher success rate
		successRate := 1.0 - step.Difficulty
		if successRate < 0.1 {
			successRate = 0.1 // Minimum success rate
		}
		successProbability *= successRate
	}

	// Base risk from success probability (0-4 points)
	baseRisk := successProbability * 4.0

	// Crown jewel value multiplier (0-3 points)
	targetNode := steps[len(steps)-1].ToNode
	crownJewelValue := s.calculateCrownJewelValue(targetNode)

	// Entry point exposure (0-1 points)
	entryNode := steps[0].FromNode
	exposureScore := s.calculateExposureScore(entryNode)

	// Trust boundaries crossed (0-1 points)
	boundariesCrossed := s.countTrustBoundariesCrossed(steps)
	boundaryPenalty := float64(boundariesCrossed) * 0.3
	if boundaryPenalty > 1.0 {
		boundaryPenalty = 1.0
	}

	// MITRE ATT&CK technique bonus (0-1 points)
	attackBonus := s.calculateAttackBonus(steps)

	// Compose final score
	compositeRisk := baseRisk + crownJewelValue + exposureScore + boundaryPenalty + attackBonus

	// Normalize to 0-10 scale
	if compositeRisk > 10.0 {
		compositeRisk = 10.0
	}

	return compositeRisk
}

// calculateCrownJewelValue scores the value of the target node
func (s *Scorer) calculateCrownJewelValue(nodeID string) float64 {
	node, exists := s.graph.Nodes[nodeID]
	if !exists {
		return 0.5
	}

	score := 1.0

	// Risk level contributes
	switch node.RiskLevel {
	case dataflow.RiskCritical:
		score += 1.5
	case dataflow.RiskHigh:
		score += 1.0
	case dataflow.RiskMedium:
		score += 0.5
	}

	// Node type contributes
	switch node.NodeType {
	case dataflow.NodeDatabase:
		score += 1.0
	case dataflow.NodeAPI:
		score += 0.3
	}

	// Findings severity
	for _, finding := range node.Findings {
		switch finding.Severity {
		case "critical":
			score += 0.3
		case "high":
			score += 0.2
		}
	}

	// Check for sensitive keywords
	labelLower := strings.ToLower(node.Label)
	keywords := []string{"secret", "credential", "password", "vault", "admin", "payment", "pii"}
	for _, keyword := range keywords {
		if strings.Contains(labelLower, keyword) {
			score += 0.2
			break
		}
	}

	if score > 3.0 {
		score = 3.0
	}

	return score
}

// calculateExposureScore scores how exposed the entry point is
func (s *Scorer) calculateExposureScore(nodeID string) float64 {
	node, exists := s.graph.Nodes[nodeID]
	if !exists {
		return 0.5
	}

	score := 0.5

	// Zone matters most
	switch node.Zone {
	case "internet":
		score = 1.0
	case "dmz":
		score = 0.7
	case "internal":
		score = 0.3
	case "secure":
		score = 0.1
	}

	// Entry point nodes are more exposed
	if node.IsEntryPoint {
		score += 0.2
	}

	// External/User nodes are public-facing
	if node.NodeType == dataflow.NodeExternal || node.NodeType == dataflow.NodeUser {
		score += 0.2
	}

	if score > 1.0 {
		score = 1.0
	}

	return score
}

// countTrustBoundariesCrossed counts how many zone transitions occur
func (s *Scorer) countTrustBoundariesCrossed(steps []AttackStep) int {
	if len(steps) == 0 {
		return 0
	}

	count := 0
	prevZone := ""

	for _, step := range steps {
		fromNode := s.graph.Nodes[step.FromNode]
		toNode := s.graph.Nodes[step.ToNode]

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

// calculateAttackBonus gives bonus for paths with known ATT&CK techniques
func (s *Scorer) calculateAttackBonus(steps []AttackStep) float64 {
	bonus := 0.0
	techniquesSeen := make(map[string]bool)

	for _, step := range steps {
		if step.MitreID != "" && !techniquesSeen[step.MitreID] {
			bonus += 0.2
			techniquesSeen[step.MitreID] = true
		}

		// Check node findings for exploitation status
		if fromNode, exists := s.graph.Nodes[step.FromNode]; exists {
			for _, finding := range fromNode.Findings {
				if len(finding.ATTACKIDs) > 0 {
					bonus += 0.1
					break
				}
			}
		}
	}

	if bonus > 1.0 {
		bonus = 1.0
	}

	return bonus
}

// RankPaths sorts paths by composite risk score (descending)
func RankPaths(paths []AttackPath) []AttackPath {
	sorted := make([]AttackPath, len(paths))
	copy(sorted, paths)

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].CompositeRisk > sorted[j].CompositeRisk
	})

	return sorted
}

// GetRiskLevel returns a string risk level based on score
func GetRiskLevel(score float64) string {
	if score >= 8.0 {
		return "CRITICAL"
	} else if score >= 6.0 {
		return "HIGH"
	} else if score >= 4.0 {
		return "MEDIUM"
	}
	return "LOW"
}

// GetRiskEmoji returns an emoji for the risk level
func GetRiskEmoji(score float64) string {
	if score >= 8.0 {
		return "🔴"
	} else if score >= 6.0 {
		return "🟠"
	} else if score >= 4.0 {
		return "🟡"
	}
	return "🟢"
}
