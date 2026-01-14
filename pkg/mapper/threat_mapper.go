package mapper

import (
	"context"
	"fmt"
	"strings"

	"github.com/Leathal1/TITO/pkg/models"
	"github.com/Leathal1/TITO/pkg/scanner"
	"github.com/Leathal1/TITO/pkg/stridelm"
)

// ThreatMapper maps threats to code assets
type ThreatMapper struct {
	threats []*models.Threat
}

// NewThreatMapper creates a new threat mapper
func NewThreatMapper(threats []*models.Threat) *ThreatMapper {
	return &ThreatMapper{
		threats: threats,
	}
}

// MappedThreat represents a threat mapped to code
type MappedThreat struct {
	Threat   *models.Threat   `json:"threat"`
	Assets   []scanner.Asset  `json:"assets"`
	DataFlows []scanner.DataFlow `json:"data_flows"`
	RiskScore float64          `json:"risk_score"`
	Mitigations []Mitigation   `json:"mitigations"`
}

// Mitigation represents a specific mitigation action
type Mitigation struct {
	ID          string           `json:"id"`
	Type        MitigationType   `json:"type"`
	Description string           `json:"description"`
	Location    scanner.Location `json:"location"`
	Priority    string           `json:"priority"` // critical, high, medium, low
	Effort      string           `json:"effort"`   // low, medium, high
	Code        string           `json:"code"`     // Example code fix
}

// MitigationType represents types of mitigations
type MitigationType string

const (
	MitigationPatch         MitigationType = "patch"
	MitigationCodeChange    MitigationType = "code_change"
	MitigationConfiguration MitigationType = "configuration"
	MitigationArchitecture  MitigationType = "architecture"
	MitigationMonitoring    MitigationType = "monitoring"
)

// MapThreatsToRepository maps threats to repository assets
func (tm *ThreatMapper) MapThreatsToRepository(ctx context.Context, repo *scanner.Repository) ([]MappedThreat, error) {
	mapped := make([]MappedThreat, 0)

	for _, threat := range tm.threats {
		mappedThreat := tm.mapSingleThreat(threat, repo)
		if len(mappedThreat.Assets) > 0 || len(mappedThreat.DataFlows) > 0 {
			mapped = append(mapped, mappedThreat)
		}
	}

	return mapped, nil
}

// mapSingleThreat maps a single threat to repository
func (tm *ThreatMapper) mapSingleThreat(threat *models.Threat, repo *scanner.Repository) MappedThreat {
	mt := MappedThreat{
		Threat:      threat,
		Assets:      make([]scanner.Asset, 0),
		DataFlows:   make([]scanner.DataFlow, 0),
		Mitigations: make([]Mitigation, 0),
	}

	// Map by CVE dependencies
	if len(threat.CVEIDs) > 0 {
		mt.Assets = append(mt.Assets, tm.findAffectedDependencies(threat, repo)...)
	}

	// Map by STRIDE-LM category
	if threat.StrideProfile != nil {
		categoryAssets := tm.findAssetsByCategory(threat.StrideProfile.PrimaryCategory, repo)
		mt.Assets = append(mt.Assets, categoryAssets...)

		// Find affected data flows
		categoryFlows := tm.findFlowsByCategory(threat.StrideProfile.PrimaryCategory, repo)
		mt.DataFlows = append(mt.DataFlows, categoryFlows...)
	}

	// Generate mitigations
	mt.Mitigations = tm.generateMitigations(threat, mt.Assets, repo)

	// Calculate risk score
	mt.RiskScore = tm.calculateRiskScore(threat, mt.Assets, mt.DataFlows)

	return mt
}

// findAffectedDependencies finds dependencies affected by CVE
func (tm *ThreatMapper) findAffectedDependencies(threat *models.Threat, repo *scanner.Repository) []scanner.Asset {
	affected := make([]scanner.Asset, 0)

	for _, cveID := range threat.CVEIDs {
		// Check dependencies
		for _, dep := range repo.Dependencies {
			// Simple name matching - real implementation would use version ranges
			for _, indicator := range threat.Indicators {
				if strings.Contains(strings.ToLower(dep.Name), strings.ToLower(indicator.Value)) {
					// Create asset for affected dependency
					affected = append(affected, scanner.Asset{
						ID:          fmt.Sprintf("dep-%s-%s", dep.Name, cveID),
						Type:        "dependency",
						Name:        fmt.Sprintf("%s %s (vulnerable to %s)", dep.Name, dep.Version, cveID),
						Description: fmt.Sprintf("Dependency affected by %s", cveID),
						Sensitive:   true,
						Tags:        []string{"dependency", "vulnerable", cveID},
					})
				}
			}
		}
	}

	return affected
}

// findAssetsByCategory finds assets relevant to STRIDE-LM category
func (tm *ThreatMapper) findAssetsByCategory(category stridelm.Category, repo *scanner.Repository) []scanner.Asset {
	relevant := make([]scanner.Asset, 0)

	// Map STRIDE-LM categories to asset types
	categoryAssetMap := map[stridelm.Category][]scanner.AssetType{
		stridelm.Spoofing:        {scanner.AssetAuth, scanner.AssetSession},
		stridelm.Tampering:       {scanner.AssetDatabase, scanner.AssetFileSystem},
		stridelm.Repudiation:     {},
		stridelm.InfoDisclosure:  {scanner.AssetDatabase, scanner.AssetAPI, scanner.AssetSecret},
		stridelm.DenialOfService: {scanner.AssetAPI, scanner.AssetNetwork},
		stridelm.Elevation:       {scanner.AssetAuth},
		stridelm.LateralMovement: {scanner.AssetNetwork, scanner.AssetAPI},
		stridelm.Malware:         {},
	}

	targetTypes := categoryAssetMap[category]
	for _, asset := range repo.Assets {
		for _, targetType := range targetTypes {
			if asset.Type == targetType {
				relevant = append(relevant, asset)
				break
			}
		}
	}

	return relevant
}

// findFlowsByCategory finds data flows relevant to category
func (tm *ThreatMapper) findFlowsByCategory(category stridelm.Category, repo *scanner.Repository) []scanner.DataFlow {
	flows := make([]scanner.DataFlow, 0)

	// Categories that involve data flows
	switch category {
	case stridelm.Tampering, stridelm.InfoDisclosure:
		// All sensitive flows are relevant
		for _, flow := range repo.DataFlows {
			if flow.Sensitive {
				flows = append(flows, flow)
			}
		}

	case stridelm.LateralMovement:
		// Network-crossing flows
		for _, flow := range repo.DataFlows {
			if flow.DataType == "network" {
				flows = append(flows, flow)
			}
		}
	}

	return flows
}

// generateMitigations generates mitigation recommendations
func (tm *ThreatMapper) generateMitigations(threat *models.Threat, assets []scanner.Asset, repo *scanner.Repository) []Mitigation {
	mitigations := make([]Mitigation, 0)

	// CVE-based mitigations
	if len(threat.CVEIDs) > 0 {
		for _, asset := range assets {
			if asset.Type == "dependency" {
				mitigations = append(mitigations, Mitigation{
					ID:          fmt.Sprintf("mit-patch-%s", asset.ID),
					Type:        MitigationPatch,
					Description: fmt.Sprintf("Update %s to patched version", asset.Name),
					Priority:    string(threat.Severity),
					Effort:      "low",
					Code:        generatePatchCommand(asset.Name, repo.Language),
				})
			}
		}
	}

	// STRIDE-LM category mitigations
	if threat.StrideProfile != nil {
		categoryInfo := stridelm.GetCategoryInfo(threat.StrideProfile.PrimaryCategory)

		// Add top mitigations as code changes
		for i, strategy := range categoryInfo.MitigationStrategies {
			if i >= 2 {
				break // Top 2
			}

			for _, asset := range assets {
				mitigations = append(mitigations, Mitigation{
					ID:          fmt.Sprintf("mit-code-%s-%d", asset.ID, i),
					Type:        MitigationCodeChange,
					Description: strategy,
					Location:    asset.Location,
					Priority:    mapSeverityToPriority(threat.Severity),
					Effort:      "medium",
					Code:        generateMitigationCode(threat.StrideProfile.PrimaryCategory, asset, repo.Language),
				})
			}
		}
	}

	return mitigations
}

// calculateRiskScore calculates risk based on threat + code exposure
func (tm *ThreatMapper) calculateRiskScore(threat *models.Threat, assets []scanner.Asset, flows []scanner.DataFlow) float64 {
	// Base score from threat priority
	baseScore := threat.PriorityScore

	// Increase score based on number of affected assets
	assetMultiplier := 1.0 + (float64(len(assets)) * 0.1)

	// Increase for exposed assets
	exposedCount := 0
	for _, asset := range assets {
		if asset.Exposed {
			exposedCount++
		}
	}
	exposureMultiplier := 1.0 + (float64(exposedCount) * 0.2)

	// Increase for sensitive data flows
	sensitiveCount := 0
	for _, flow := range flows {
		if flow.Sensitive {
			sensitiveCount++
		}
	}
	flowMultiplier := 1.0 + (float64(sensitiveCount) * 0.15)

	score := baseScore * assetMultiplier * exposureMultiplier * flowMultiplier

	if score > 1.0 {
		return 1.0
	}
	return score
}

// Helper functions

func generatePatchCommand(depName, language string) string {
	switch language {
	case "go":
		return fmt.Sprintf("go get -u %s@latest", depName)
	case "python":
		return fmt.Sprintf("pip install --upgrade %s", depName)
	case "javascript", "typescript":
		return fmt.Sprintf("npm update %s", depName)
	default:
		return fmt.Sprintf("Update %s to latest version", depName)
	}
}

func generateMitigationCode(category stridelm.Category, asset scanner.Asset, language string) string {
	// Generate example mitigation code based on category and language
	switch category {
	case stridelm.Spoofing:
		if language == "go" {
			return `// Add authentication middleware
func AuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        token := r.Header.Get("Authorization")
        if !validateToken(token) {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }
        next.ServeHTTP(w, r)
    })
}`
		}

	case stridelm.Tampering:
		if language == "go" && asset.Type == scanner.AssetDatabase {
			return `// Use parameterized queries
stmt, err := db.Prepare("SELECT * FROM users WHERE id = ?")
if err != nil {
    return err
}
defer stmt.Close()
rows, err := stmt.Query(userID)  // Safe from SQL injection`
		}

	case stridelm.InfoDisclosure:
		if language == "go" {
			return `// Add encryption for sensitive data
encrypted, err := encryptData(sensitiveData)
if err != nil {
    return err
}
// Store encrypted data
db.Exec("INSERT INTO secrets (data) VALUES (?)", encrypted)`
		}
	}

	return "// Implement appropriate security control"
}

func mapSeverityToPriority(severity models.ThreatSeverity) string {
	switch severity {
	case models.SeverityCritical:
		return "critical"
	case models.SeverityHigh:
		return "high"
	case models.SeverityMedium:
		return "medium"
	case models.SeverityLow:
		return "low"
	default:
		return "low"
	}
}
