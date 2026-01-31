package diff

import (
	"github.com/Leathal1/TITO/pkg/attackpath"
	"github.com/Leathal1/TITO/pkg/models"
	"github.com/Leathal1/TITO/pkg/scan"
	"github.com/Leathal1/TITO/pkg/scanner"
)

// DiffResult represents the complete diff between two scans
type DiffResult struct {
	Base *scan.ScanResult `json:"base"`
	Head *scan.ScanResult `json:"head"`

	// Asset changes
	AddedAssets    []scanner.Asset `json:"addedAssets"`
	RemovedAssets  []scanner.Asset `json:"removedAssets"`
	ModifiedAssets []AssetDiff     `json:"modifiedAssets"`

	// Threat changes
	AddedThreats   []*models.Threat `json:"addedThreats"`
	RemovedThreats []*models.Threat `json:"removedThreats"`

	// Data flow changes
	AddedFlows   []scanner.DataFlow `json:"addedFlows"`
	RemovedFlows []scanner.DataFlow `json:"removedFlows"`

	// Attack path changes
	AddedPaths   []attackpath.AttackPath `json:"addedPaths"`
	RemovedPaths []attackpath.AttackPath `json:"removedPaths"`

	// Dependency changes
	AddedDeps   []scanner.Dependency `json:"addedDeps"`
	RemovedDeps []scanner.Dependency `json:"removedDeps"`
	UpdatedDeps []DependencyDiff     `json:"updatedDeps"`

	// Risk score delta
	RiskDelta RiskDelta `json:"riskDelta"`

	// Summary
	Summary DiffSummary `json:"summary"`
}

// AssetDiff represents a change in an asset
type AssetDiff struct {
	Before  scanner.Asset `json:"before"`
	After   scanner.Asset `json:"after"`
	Changes []string      `json:"changes"` // human-readable change descriptions
}

// DependencyDiff represents a dependency version change
type DependencyDiff struct {
	Name       string `json:"name"`
	OldVersion string `json:"oldVersion"`
	NewVersion string `json:"newVersion"`
}

// RiskDelta represents the change in risk between scans
type RiskDelta struct {
	BaseMaxRisk      float64 `json:"baseMaxRisk"`
	HeadMaxRisk      float64 `json:"headMaxRisk"`
	BaseAvgRisk      float64 `json:"baseAvgRisk"`
	HeadAvgRisk      float64 `json:"headAvgRisk"`
	ThreatCountDelta int     `json:"threatCountDelta"`
	RiskDirection    string  `json:"riskDirection"` // "increased", "decreased", "unchanged"
}

// DiffSummary provides a high-level summary of changes
type DiffSummary struct {
	TotalChanges    int    `json:"totalChanges"`
	NewHighSeverity int    `json:"newHighSeverity"`
	ResolvedThreats int    `json:"resolvedThreats"`
	NewAttackPaths  int    `json:"newAttackPaths"`
	RiskVerdict     string `json:"riskVerdict"`   // "PASS", "WARN", "FAIL"
	VerdictReason   string `json:"verdictReason"` // Human-readable explanation
}

// VerdictConfig configures verdict thresholds
type VerdictConfig struct {
	FailOnCritical      bool    `json:"failOnCritical"`      // Fail if any new critical threats
	FailOnHigh          bool    `json:"failOnHigh"`          // Fail if any new high threats
	FailOnRiskIncrease  bool    `json:"failOnRiskIncrease"`  // Fail if overall risk increased
	WarnOnHigh          bool    `json:"warnOnHigh"`          // Warn if any new high threats
	WarnOnRiskIncrease  bool    `json:"warnOnRiskIncrease"`  // Warn if overall risk increased
	MaxRiskThreshold    float64 `json:"maxRiskThreshold"`    // Fail if max risk exceeds this
	RiskIncreasePercent float64 `json:"riskIncreasePercent"` // Fail if risk increases by this %
}

// DefaultVerdictConfig returns sensible defaults
func DefaultVerdictConfig() VerdictConfig {
	return VerdictConfig{
		FailOnCritical:      true,
		FailOnHigh:          false,
		FailOnRiskIncrease:  false,
		WarnOnHigh:          true,
		WarnOnRiskIncrease:  true,
		MaxRiskThreshold:    0.8,
		RiskIncreasePercent: 0.2, // 20% increase
	}
}

// FailOnCriticalConfig returns config that fails only on critical
func FailOnCriticalConfig() VerdictConfig {
	return VerdictConfig{
		FailOnCritical:     true,
		FailOnHigh:         false,
		WarnOnHigh:         true,
		WarnOnRiskIncrease: true,
	}
}

// FailOnHighConfig returns config that fails on high+ severity
func FailOnHighConfig() VerdictConfig {
	return VerdictConfig{
		FailOnCritical: true,
		FailOnHigh:     true,
		WarnOnHigh:     false, // Already failing
	}
}

// FailOnAnyConfig returns config that fails on any new threat
func FailOnAnyConfig() VerdictConfig {
	return VerdictConfig{
		FailOnCritical:     true,
		FailOnHigh:         true,
		FailOnRiskIncrease: true,
	}
}
