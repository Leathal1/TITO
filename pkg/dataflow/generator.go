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
	diagram := g.BuildDiagramData(repo, threats)

	// Generate HTML
	html := g.generateHTML(diagram)

	// Write to file
	if err := os.WriteFile(outputPath, []byte(html), 0644); err != nil {
		return fmt.Errorf("failed to write diagram: %w", err)
	}

	return nil
}

// BuildDiagramData builds the diagram data structure from repository and threats
func (g *Generator) BuildDiagramData(repo *scanner.Repository, threats []*models.Threat) *DiagramData {
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

	// Group assets by type and location to create meaningful nodes
	assetGroups := g.groupAssets(repo.Assets)
	
	// Convert asset groups to nodes
	nodeIDMap := make(map[string]string) // Maps asset ID to node ID
	
	for groupKey, assets := range assetGroups {
		if len(assets) == 0 {
			continue
		}

		// Use first asset as representative
		asset := assets[0]
		nodeID := groupKey

		node := Node{
			ID:          nodeID,
			Label:       g.generateNodeLabel(asset.Type, assets),
			Type:        mapAssetTypeToNodeType(asset.Type),
			RiskLevel:   calculateGroupRisk(assets, threats),
			Description: g.generateNodeDescription(assets),
			Threats:     make([]string, 0),
			Findings:    make([]Finding, 0),
		}

		// Map all assets in this group to this node
		for _, a := range assets {
			nodeIDMap[a.ID] = nodeID
		}

		// Find related threats for any asset in the group
		threatMap := make(map[string]bool)
		for _, a := range assets {
			for _, threat := range threats {
				if isAssetAffected(a, threat) && !threatMap[threat.ID] {
					threatMap[threat.ID] = true
					node.Threats = append(node.Threats, threat.ID)
					node.Findings = append(node.Findings, convertThreatToFinding(threat))
				}
			}
		}

		diagram.Nodes = append(diagram.Nodes, node)
	}

	// Convert data flows to edges with proper node references
	edgeMap := make(map[string]bool) // Deduplicate edges
	for _, flow := range repo.DataFlows {
		// Find the source and target asset IDs
		sourceNodeID := findNodeForLocation(flow.Source, nodeIDMap, repo.Assets)
		targetNodeID := findNodeForLocation(flow.Destination, nodeIDMap, repo.Assets)

		if sourceNodeID == "" || targetNodeID == "" {
			continue // Skip if we can't find nodes
		}

		edgeKey := sourceNodeID + "->" + targetNodeID
		if edgeMap[edgeKey] {
			continue // Skip duplicate edges
		}
		edgeMap[edgeKey] = true

		edge := Edge{
			ID:        fmt.Sprintf("edge-%s-%s", sourceNodeID, targetNodeID),
			Source:    sourceNodeID,
			Target:    targetNodeID,
			Label:     g.generateEdgeLabel(flow),
			DataType:  flow.DataType,
			Sensitive: flow.Sensitive,
			Encrypted: detectEncryption(flow, repo.Assets),
			Protocols: inferProtocols(flow),
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

// groupAssets groups assets by type and file for better visualization
func (g *Generator) groupAssets(assets []scanner.Asset) map[string][]scanner.Asset {
	groups := make(map[string][]scanner.Asset)

	for _, asset := range assets {
		// Group by type and file directory
		dir := strings.Split(asset.Location.File, "/")[0]
		groupKey := fmt.Sprintf("%s-%s", asset.Type, dir)
		groups[groupKey] = append(groups[groupKey], asset)
	}

	return groups
}

// generateNodeLabel creates a descriptive label for a node
func (g *Generator) generateNodeLabel(assetType scanner.AssetType, assets []scanner.Asset) string {
	count := len(assets)
	
	switch assetType {
	case scanner.AssetAPI:
		if count == 1 {
			return assets[0].Name
		}
		return fmt.Sprintf("API Endpoints (%d)", count)
	case scanner.AssetDatabase:
		return fmt.Sprintf("Database Operations (%d)", count)
	case scanner.AssetAuth:
		return fmt.Sprintf("Authentication (%d)", count)
	case scanner.AssetSecret:
		return fmt.Sprintf("Secrets/Config (%d)", count)
	case scanner.AssetFileSystem:
		return fmt.Sprintf("File Operations (%d)", count)
	case scanner.AssetNetwork:
		return fmt.Sprintf("External APIs (%d)", count)
	case scanner.AssetCache:
		return fmt.Sprintf("Cache (%d)", count)
	case scanner.AssetQueue:
		return fmt.Sprintf("Message Queue (%d)", count)
	case scanner.AssetCrypto:
		return fmt.Sprintf("Cryptography (%d)", count)
	default:
		return fmt.Sprintf("%s (%d)", assetType, count)
	}
}

// generateNodeDescription creates a detailed description
func (g *Generator) generateNodeDescription(assets []scanner.Asset) string {
	if len(assets) == 1 {
		return assets[0].Description
	}
	
	files := make(map[string]bool)
	for _, a := range assets {
		files[a.Location.File] = true
	}
	
	return fmt.Sprintf("%d assets across %d files", len(assets), len(files))
}

// generateEdgeLabel creates a descriptive edge label
func (g *Generator) generateEdgeLabel(flow scanner.DataFlow) string {
	label := flow.DataType
	
	// Add sensitivity indicator
	if flow.Sensitive {
		label = "🔒 " + label
	}
	
	// Add threat count if any
	if len(flow.Threats) > 0 {
		label = fmt.Sprintf("%s (%d threats)", label, len(flow.Threats))
	}
	
	return label
}

// findNodeForLocation finds the node ID that contains a given location
func findNodeForLocation(loc scanner.Location, nodeIDMap map[string]string, assets []scanner.Asset) string {
	// Find asset at this location
	for _, asset := range assets {
		if asset.Location.File == loc.File && asset.Location.Line == loc.Line {
			if nodeID, ok := nodeIDMap[asset.ID]; ok {
				return nodeID
			}
		}
	}
	return ""
}

// detectEncryption checks if the flow involves encryption
func detectEncryption(flow scanner.DataFlow, assets []scanner.Asset) bool {
	// Check if either source or destination involves crypto
	for _, asset := range assets {
		if (asset.Location == flow.Source || asset.Location == flow.Destination) &&
			asset.Type == scanner.AssetCrypto {
			return true
		}
	}
	return false
}

// inferProtocols infers communication protocols from data type
func inferProtocols(flow scanner.DataFlow) []string {
	protocols := make([]string, 0)
	
	dataType := strings.ToLower(flow.DataType)
	
	if strings.Contains(dataType, "http") || strings.Contains(dataType, "api") {
		protocols = append(protocols, "HTTP")
	}
	if strings.Contains(dataType, "sql") || strings.Contains(dataType, "database") {
		protocols = append(protocols, "SQL")
	}
	if strings.Contains(dataType, "queue") || strings.Contains(dataType, "message") {
		protocols = append(protocols, "AMQP")
	}
	
	return protocols
}

// calculateGroupRisk calculates risk for a group of assets
func calculateGroupRisk(assets []scanner.Asset, threats []*models.Threat) RiskLevel {
	maxRisk := RiskLow

	// Check each asset in the group
	for _, asset := range assets {
		assetRisk := calculateAssetRisk(asset, threats)
		if assetRisk > maxRisk {
			maxRisk = assetRisk
		}
	}

	return maxRisk
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
