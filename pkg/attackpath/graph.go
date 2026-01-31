package attackpath

import (
	"strings"

	"github.com/Leathal1/TITO/pkg/dataflow"
)

// GraphBuilder builds an attack graph from diagram data
type GraphBuilder struct {
	diagram *dataflow.DiagramData
}

// NewGraphBuilder creates a new graph builder
func NewGraphBuilder(diagram *dataflow.DiagramData) *GraphBuilder {
	return &GraphBuilder{diagram: diagram}
}

// Build converts DiagramData into AttackGraph
func (gb *GraphBuilder) Build() *AttackGraph {
	graph := &AttackGraph{
		Nodes:       make(map[string]*AttackNode),
		Edges:       make([]*AttackEdge, 0),
		EntryPoints: make([]string, 0),
		CrownJewels: make([]string, 0),
	}

	// Map zones from trust boundaries
	zoneMap := gb.buildZoneMap()

	// Convert nodes
	for _, node := range gb.diagram.Nodes {
		attackNode := &AttackNode{
			ID:             node.ID,
			Label:          node.Label,
			NodeType:       node.Type,
			RiskLevel:      node.RiskLevel,
			Zone:           zoneMap[node.ID],
			Findings:       node.Findings,
			IsEntryPoint:   false,
			IsCrownJewel:   false,
			Exploitability: gb.calculateExploitability(node.Findings),
		}

		// Identify entry points
		if gb.isEntryPoint(node, zoneMap[node.ID]) {
			attackNode.IsEntryPoint = true
			graph.EntryPoints = append(graph.EntryPoints, node.ID)
		}

		// Identify crown jewels
		if gb.isCrownJewel(node) {
			attackNode.IsCrownJewel = true
			graph.CrownJewels = append(graph.CrownJewels, node.ID)
		}

		graph.Nodes[node.ID] = attackNode
	}

	// Convert edges
	for _, edge := range gb.diagram.Edges {
		attackEdge := &AttackEdge{
			Source:        edge.Source,
			Target:        edge.Target,
			Technique:     gb.determineTechnique(edge),
			Difficulty:    gb.calculateEdgeDifficulty(edge, zoneMap),
			RequiredPriv:  gb.determineRequiredPrivilege(edge),
			DataSensitive: edge.Sensitive,
			Encrypted:     edge.Encrypted,
			MitreID:       gb.extractMitreID(edge),
		}
		graph.Edges = append(graph.Edges, attackEdge)
	}

	return graph
}

// buildZoneMap maps node IDs to their trust boundary zones
func (gb *GraphBuilder) buildZoneMap() map[string]string {
	zoneMap := make(map[string]string)
	for _, boundary := range gb.diagram.TrustBoundaries {
		for _, nodeID := range boundary.Nodes {
			zoneMap[nodeID] = boundary.Zone
		}
	}
	// Default zone for unmapped nodes
	for _, node := range gb.diagram.Nodes {
		if _, exists := zoneMap[node.ID]; !exists {
			zoneMap[node.ID] = "internal"
		}
	}
	return zoneMap
}

// isEntryPoint determines if a node is an attack entry point
func (gb *GraphBuilder) isEntryPoint(node dataflow.Node, zone string) bool {
	// Nodes in internet zone
	if zone == "internet" {
		return true
	}

	// External or user-facing nodes
	if node.Type == dataflow.NodeExternal || node.Type == dataflow.NodeUser {
		return true
	}

	// API gateways are typically entry points
	if node.Type == dataflow.NodeAPI {
		return true
	}

	// Check if node has no incoming edges from internal zones (exposed endpoint)
	hasInternalSource := false
	for _, edge := range gb.diagram.Edges {
		if edge.Target == node.ID {
			sourceZone := gb.getNodeZone(edge.Source)
			if sourceZone == "internal" || sourceZone == "secure" {
				hasInternalSource = true
				break
			}
		}
	}

	return !hasInternalSource && (zone == "dmz" || node.Type == dataflow.NodeAPI)
}

// isCrownJewel determines if a node is a high-value target
func (gb *GraphBuilder) isCrownJewel(node dataflow.Node) bool {
	// Databases are usually crown jewels
	if node.Type == dataflow.NodeDatabase {
		return true
	}

	// Critical risk level nodes
	if node.RiskLevel == dataflow.RiskCritical {
		return true
	}

	// Nodes with sensitive data flows
	for _, edge := range gb.diagram.Edges {
		if (edge.Source == node.ID || edge.Target == node.ID) && edge.Sensitive {
			return true
		}
	}

	// Check label for keywords
	labelLower := strings.ToLower(node.Label)
	keywords := []string{"secret", "credential", "password", "key", "vault", "admin", "auth"}
	for _, keyword := range keywords {
		if strings.Contains(labelLower, keyword) {
			return true
		}
	}

	return false
}

// calculateExploitability calculates node exploitability based on findings
func (gb *GraphBuilder) calculateExploitability(findings []dataflow.Finding) float64 {
	if len(findings) == 0 {
		return 0.1 // Base exploitability
	}

	score := 0.0
	for _, finding := range findings {
		switch finding.Severity {
		case "critical":
			score += 0.4
		case "high":
			score += 0.3
		case "medium":
			score += 0.2
		case "low":
			score += 0.1
		}
	}

	// Normalize by number of findings (diminishing returns)
	exploitability := score / (1.0 + float64(len(findings))*0.1)
	if exploitability > 1.0 {
		return 1.0
	}
	return exploitability
}

// calculateEdgeDifficulty calculates traversal difficulty for an edge
func (gb *GraphBuilder) calculateEdgeDifficulty(edge dataflow.Edge, zoneMap map[string]string) float64 {
	difficulty := 0.3 // Base difficulty

	// Encryption makes it harder
	if edge.Encrypted {
		difficulty += 0.3
	}

	// Crossing trust boundaries is harder
	sourceZone := zoneMap[edge.Source]
	targetZone := zoneMap[edge.Target]
	if sourceZone != targetZone {
		difficulty += 0.2
	}

	// Sensitive data is attractive (reduces difficulty for attacker)
	if edge.Sensitive {
		difficulty -= 0.1
	}

	// Normalize to 0.0-1.0
	if difficulty < 0.0 {
		difficulty = 0.05
	}
	if difficulty > 1.0 {
		difficulty = 1.0
	}

	return difficulty
}

// determineRequiredPrivilege determines the privilege level needed
func (gb *GraphBuilder) determineRequiredPrivilege(edge dataflow.Edge) string {
	// Check protocols for authentication requirements
	for _, protocol := range edge.Protocols {
		protocolLower := strings.ToLower(protocol)
		if strings.Contains(protocolLower, "auth") || strings.Contains(protocolLower, "oauth") {
			return "high"
		}
		if strings.Contains(protocolLower, "api") {
			return "low"
		}
	}

	// Check if data is sensitive (usually requires auth)
	if edge.Sensitive {
		return "low"
	}

	return "none"
}

// determineTechnique determines attack technique for edge traversal
func (gb *GraphBuilder) determineTechnique(edge dataflow.Edge) string {
	// Check for specific protocols
	for _, protocol := range edge.Protocols {
		protocolLower := strings.ToLower(protocol)
		if strings.Contains(protocolLower, "http") || strings.Contains(protocolLower, "api") {
			return "API Exploitation"
		}
		if strings.Contains(protocolLower, "sql") || strings.Contains(protocolLower, "db") {
			return "Database Access"
		}
		if strings.Contains(protocolLower, "rpc") {
			return "Remote Procedure Call"
		}
	}

	// Check label for hints
	labelLower := strings.ToLower(edge.Label)
	if strings.Contains(labelLower, "query") {
		return "Query Injection"
	}
	if strings.Contains(labelLower, "command") {
		return "Command Injection"
	}

	return "Lateral Movement"
}

// extractMitreID extracts MITRE ATT&CK ID from edge threats
func (gb *GraphBuilder) extractMitreID(edge dataflow.Edge) string {
	// Check findings from related nodes for MITRE IDs
	// For now, map common techniques
	technique := strings.ToLower(gb.determineTechnique(edge))
	
	if strings.Contains(technique, "injection") {
		return "T1190" // Exploit Public-Facing Application
	}
	if strings.Contains(technique, "api") {
		return "T1212" // Exploitation for Credential Access
	}
	if strings.Contains(technique, "lateral") {
		return "T1021" // Remote Services
	}

	return ""
}

// getNodeZone is a helper to get a node's zone
func (gb *GraphBuilder) getNodeZone(nodeID string) string {
	for _, boundary := range gb.diagram.TrustBoundaries {
		for _, id := range boundary.Nodes {
			if id == nodeID {
				return boundary.Zone
			}
		}
	}
	return "internal"
}
