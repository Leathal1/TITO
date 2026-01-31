package scan

import (
	"time"

	"github.com/Leathal1/TITO/pkg/attackpath"
	"github.com/Leathal1/TITO/pkg/mapper"
	"github.com/Leathal1/TITO/pkg/models"
	"github.com/Leathal1/TITO/pkg/scanner"
)

// ScanResult represents a complete, serializable scan output
type ScanResult struct {
	Version       string                  `json:"version"`
	Timestamp     time.Time               `json:"timestamp"`
	Repository    RepositoryInfo          `json:"repository"`
	Assets        []scanner.Asset         `json:"assets"`
	DataFlows     []scanner.DataFlow      `json:"dataFlows"`
	Dependencies  []scanner.Dependency    `json:"dependencies"`
	Threats       []*models.Threat        `json:"threats"`
	MappedThreats []mapper.MappedThreat   `json:"mappedThreats"`
	AttackPaths   []attackpath.AttackPath `json:"attackPaths"`
	Stats         ScanStats               `json:"stats"`
}

// RepositoryInfo contains repository metadata
type RepositoryInfo struct {
	URL       string `json:"url"`
	Branch    string `json:"branch"`
	Language  string `json:"language"`
	Framework string `json:"framework"`
	CommitSHA string `json:"commitSha"`
}

// ScanStats contains summary statistics
type ScanStats struct {
	TotalAssets      int     `json:"totalAssets"`
	TotalDataFlows   int     `json:"totalDataFlows"`
	TotalThreats     int     `json:"totalThreats"`
	CriticalThreats  int     `json:"criticalThreats"`
	HighThreats      int     `json:"highThreats"`
	TotalAttackPaths int     `json:"totalAttackPaths"`
	MaxRiskScore     float64 `json:"maxRiskScore"`
	AvgRiskScore     float64 `json:"avgRiskScore"`
}

// CalculateStats computes statistics from scan data
func (sr *ScanResult) CalculateStats() {
	sr.Stats.TotalAssets = len(sr.Assets)
	sr.Stats.TotalDataFlows = len(sr.DataFlows)
	sr.Stats.TotalThreats = len(sr.Threats)
	sr.Stats.TotalAttackPaths = len(sr.AttackPaths)

	// Count threats by severity
	sr.Stats.CriticalThreats = 0
	sr.Stats.HighThreats = 0
	for _, threat := range sr.Threats {
		if threat.Severity == models.SeverityCritical {
			sr.Stats.CriticalThreats++
		} else if threat.Severity == models.SeverityHigh {
			sr.Stats.HighThreats++
		}
	}

	// Calculate risk scores
	sr.Stats.MaxRiskScore = 0.0
	totalRisk := 0.0
	riskCount := 0

	for _, mt := range sr.MappedThreats {
		if mt.RiskScore > sr.Stats.MaxRiskScore {
			sr.Stats.MaxRiskScore = mt.RiskScore
		}
		totalRisk += mt.RiskScore
		riskCount++
	}

	// Also consider attack path composite risk
	for _, ap := range sr.AttackPaths {
		normalized := ap.CompositeRisk / 10.0 // Convert 0-10 to 0-1
		if normalized > sr.Stats.MaxRiskScore {
			sr.Stats.MaxRiskScore = normalized
		}
		totalRisk += normalized
		riskCount++
	}

	if riskCount > 0 {
		sr.Stats.AvgRiskScore = totalRisk / float64(riskCount)
	}
}

// NewScanResult creates a new scan result with version and timestamp
func NewScanResult() *ScanResult {
	return &ScanResult{
		Version:       "1.0",
		Timestamp:     time.Now(),
		Assets:        make([]scanner.Asset, 0),
		DataFlows:     make([]scanner.DataFlow, 0),
		Dependencies:  make([]scanner.Dependency, 0),
		Threats:       make([]*models.Threat, 0),
		MappedThreats: make([]mapper.MappedThreat, 0),
		AttackPaths:   make([]attackpath.AttackPath, 0),
	}
}
