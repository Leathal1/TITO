package dataflow

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Leathal1/TITO/pkg/models"
	"github.com/Leathal1/TITO/pkg/scanner"
)

// Generator generates data flow diagrams
type Generator struct{}

// NewGenerator creates a new data flow diagram generator
func NewGenerator() *Generator {
	return &Generator{}
}

// GenerateFromRepository generates a diagram from scanned repository
func (g *Generator) GenerateFromRepository(
	repo *scanner.Repository,
	threats []*models.Threat,
	outputPath string,
) error {
	// Build diagram data
	diagram := g.buildDiagramData(repo, threats)

	// Generate HTML
	html := g.generateHTML(diagram)

	// Write to file
	if err := os.WriteFile(outputPath, []byte(html), 0644); err != nil {
		return fmt.Errorf("failed to write diagram: %w", err)
	}

	return nil
}

// buildDiagramData builds the diagram data structure from repository and threats
func (g *Generator) buildDiagramData(repo *scanner.Repository, threats []*models.Threat) *DiagramData {
	diagram := &DiagramData{
		Nodes:           make([]Node, 0),
		Edges:           make([]Edge, 0),
		TrustBoundaries: make([]TrustBoundary, 0),
		Metadata: Metadata{
			Title:       "Threat Model: " + repo.URL,
			Description: "Data Flow Diagram with STRIDE-LM and MAESTRO Analysis",
			Generated:   time.Now().Format(time.RFC3339),
			Repository:  repo.URL,
			Branch:      repo.Branch,
		},
	}

	// Convert assets to nodes
	nodeMap := make(map[string]bool)
	for _, asset := range repo.Assets {
		if nodeMap[asset.ID] {
			continue // Skip duplicates
		}
		nodeMap[asset.ID] = true

		node := Node{
			ID:          asset.ID,
			Label:       asset.Name,
			Type:        mapAssetTypeToNodeType(asset.Type),
			RiskLevel:   calculateAssetRisk(asset, threats),
			Description: asset.Description,
			Threats:     make([]string, 0),
			Findings:    make([]Finding, 0),
		}

		// Find related threats
		for _, threat := range threats {
			// Simple matching - in real implementation, use proper threat mapper
			if isAssetAffected(asset, threat) {
				node.Threats = append(node.Threats, threat.ID)
				node.Findings = append(node.Findings, convertThreatToFinding(threat))
			}
		}

		diagram.Nodes = append(diagram.Nodes, node)
	}

	// Convert data flows to edges
	for _, flow := range repo.DataFlows {
		edge := Edge{
			ID:        flow.ID,
			Source:    flow.Source.File + ":" + fmt.Sprint(flow.Source.Line),
			Target:    flow.Destination.File + ":" + fmt.Sprint(flow.Destination.Line),
			Label:     flow.DataType,
			DataType:  flow.DataType,
			Sensitive: flow.Sensitive,
			Encrypted: false, // Would need to infer from code analysis
			Protocols: make([]string, 0),
			Threats:   flow.Threats,
		}
		diagram.Edges = append(diagram.Edges, edge)
	}

	// Create trust boundaries
	diagram.TrustBoundaries = g.inferTrustBoundaries(diagram.Nodes)

	// Update metadata counts
	diagram.Metadata.TotalNodes = len(diagram.Nodes)
	diagram.Metadata.TotalEdges = len(diagram.Edges)
	diagram.Metadata.TotalThreats = len(threats)

	return diagram
}

// generateHTML generates the complete HTML file
func (g *Generator) generateHTML(diagram *DiagramData) string {
	// Convert diagram data to JSON
	diagramJSON, _ := json.MarshalIndent(diagram, "", "  ")

	// Replace placeholder in template
	html := htmlTemplate
	html = strings.Replace(html, "{{DIAGRAM_DATA}}", string(diagramJSON), 1)
	html = strings.Replace(html, "{{TITLE}}", diagram.Metadata.Title, -1)

	return html
}

// Helper functions

func mapAssetTypeToNodeType(assetType scanner.AssetType) NodeType {
	switch assetType {
	case scanner.AssetAPI:
		return NodeAPI
	case scanner.AssetDatabase:
		return NodeDatabase
	case scanner.AssetAuth:
		return NodeService
	case scanner.AssetSecret:
		return NodeExternal
	case scanner.AssetFileSystem:
		return NodeService
	case scanner.AssetNetwork:
		return NodeExternal
	case scanner.AssetCrypto:
		return NodeService
	case scanner.AssetSession:
		return NodeCache
	case scanner.AssetCache:
		return NodeCache
	case scanner.AssetQueue:
		return NodeQueue
	default:
		return NodeService
	}
}

func calculateAssetRisk(asset scanner.Asset, threats []*models.Threat) RiskLevel {
	maxRisk := RiskLow

	// Assets marked as sensitive or exposed are higher risk
	if asset.Sensitive && asset.Exposed {
		maxRisk = RiskHigh
	} else if asset.Sensitive || asset.Exposed {
		maxRisk = RiskMedium
	}

	// Check associated threats
	for _, threat := range threats {
		if isAssetAffected(asset, threat) {
			switch threat.Severity {
			case models.SeverityCritical:
				return RiskCritical // Immediately return critical
			case models.SeverityHigh:
				if maxRisk < RiskHigh {
					maxRisk = RiskHigh
				}
			case models.SeverityMedium:
				if maxRisk < RiskMedium {
					maxRisk = RiskMedium
				}
			}
		}
	}

	return maxRisk
}

func isAssetAffected(asset scanner.Asset, threat *models.Threat) bool {
	// Simple heuristic - check if asset type/name matches threat keywords
	assetStr := strings.ToLower(asset.Name + " " + string(asset.Type))
	threatStr := strings.ToLower(threat.Title + " " + threat.Description)

	// Common keywords that link assets to threats
	keywords := []string{"api", "database", "auth", "secret", "credential"}
	for _, keyword := range keywords {
		if strings.Contains(assetStr, keyword) && strings.Contains(threatStr, keyword) {
			return true
		}
	}

	return false
}

func convertThreatToFinding(threat *models.Threat) Finding {
	finding := Finding{
		ID:          threat.ID,
		Title:       threat.Title,
		Description: threat.Description,
		Severity:    string(threat.Severity),
		Mitigations: threat.RecommendedActions,
		ATTACKIDs:   threat.MitreAttackIDs,
		Source:      "TITO",
	}

	if threat.StrideProfile != nil {
		finding.STRIDE = threat.StrideProfile.String()
	}

	return finding
}

func (g *Generator) inferTrustBoundaries(nodes []Node) []TrustBoundary {
	boundaries := make([]TrustBoundary, 0)

	// Group nodes by type to infer boundaries
	internetNodes := make([]string, 0)
	internalNodes := make([]string, 0)
	dataNodes := make([]string, 0)

	for _, node := range nodes {
		switch node.Type {
		case NodeExternal, NodeAPI:
			internetNodes = append(internetNodes, node.ID)
		case NodeDatabase, NodeCache, NodeQueue:
			dataNodes = append(dataNodes, node.ID)
		default:
			internalNodes = append(internalNodes, node.ID)
		}
	}

	if len(internetNodes) > 0 {
		boundaries = append(boundaries, TrustBoundary{
			ID:    "boundary-internet",
			Name:  "Internet-Facing",
			Nodes: internetNodes,
			Color: "#ff4444",
			Zone:  "internet",
		})
	}

	if len(internalNodes) > 0 {
		boundaries = append(boundaries, TrustBoundary{
			ID:    "boundary-internal",
			Name:  "Internal Services",
			Nodes: internalNodes,
			Color: "#ffd700",
			Zone:  "internal",
		})
	}

	if len(dataNodes) > 0 {
		boundaries = append(boundaries, TrustBoundary{
			ID:    "boundary-data",
			Name:  "Data Layer",
			Nodes: dataNodes,
			Color: "#00d4aa",
			Zone:  "secure",
		})
	}

	return boundaries
}
