package drift

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Leathal1/TITO/v2/pkg/models"
	"github.com/Leathal1/TITO/v2/pkg/scan"
	"github.com/Leathal1/TITO/v2/pkg/scanner"
)

// DriftDetector handles baseline management and drift comparison
type DriftDetector struct {
	baselineDir string
}

// NewDriftDetector creates a new drift detector
func NewDriftDetector() *DriftDetector {
	homeDir, _ := os.UserHomeDir()
	baselineDir := filepath.Join(homeDir, ".tito", "baselines")
	
	// Ensure baseline directory exists
	os.MkdirAll(baselineDir, 0755)
	
	return &DriftDetector{
		baselineDir: baselineDir,
	}
}

// DriftReport represents the result of comparing two scans
type DriftReport struct {
	BaselineScan   *scan.ScanResult `json:"baselineScan"`
	CurrentScan    *scan.ScanResult `json:"currentScan"`
	
	// Overall drift score (0-100, higher = more drift/worse)
	DriftScore     int              `json:"driftScore"`
	
	// Component-level changes
	ChangedComponents []ComponentChange `json:"changedComponents"`
	
	// Threat changes
	NewThreats     []*models.Threat `json:"newThreats"`
	RemovedThreats []*models.Threat `json:"removedThreats"`
	
	// Mitigation changes
	RemovedMitigations []string `json:"removedMitigations"`
	
	// Trust boundary violations
	NewTrustBoundaryViolations []string `json:"newTrustBoundaryViolations"`
	
	// Data flow changes bypassing controls
	NewUncontrolledFlows []scanner.DataFlow `json:"newUncontrolledFlows"`
	
	// Trend direction
	TrendDirection string `json:"trendDirection"` // "improving", "stable", "degrading"
	
	// Timestamp
	ComparedAt     time.Time `json:"comparedAt"`
}

// ComponentChange represents a change in a system component
type ComponentChange struct {
	ComponentName string   `json:"componentName"`
	ChangeType    string   `json:"changeType"` // "added", "removed", "modified"
	Changes       []string `json:"changes"`    // Human-readable change descriptions
	RiskDelta     float64  `json:"riskDelta"`  // Change in risk score
}

// SetBaseline saves a scan result as the baseline for future drift detection
func (dd *DriftDetector) SetBaseline(scanResult *scan.ScanResult, name string) error {
	if name == "" {
		name = "default"
	}
	
	baselinePath := filepath.Join(dd.baselineDir, name+".json")
	
	if err := scan.SaveResult(scanResult, baselinePath); err != nil {
		return fmt.Errorf("failed to save baseline: %w", err)
	}
	
	fmt.Printf("✓ Baseline saved: %s\n", baselinePath)
	return nil
}

// LoadBaseline loads a baseline scan from storage
func (dd *DriftDetector) LoadBaseline(name string) (*scan.ScanResult, error) {
	if name == "" {
		name = "default"
	}
	
	baselinePath := filepath.Join(dd.baselineDir, name+".json")
	
	baseline, err := scan.LoadResult(baselinePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load baseline: %w", err)
	}
	
	return baseline, nil
}

// ListBaselines returns all available baseline names
func (dd *DriftDetector) ListBaselines() ([]string, error) {
	entries, err := os.ReadDir(dd.baselineDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("failed to list baselines: %w", err)
	}
	
	baselines := make([]string, 0)
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			name := entry.Name()
			name = name[:len(name)-5] // Remove .json extension
			baselines = append(baselines, name)
		}
	}
	
	return baselines, nil
}

// Compare compares a current scan against a baseline and generates a drift report
func (dd *DriftDetector) Compare(current, baseline *scan.ScanResult) *DriftReport {
	report := &DriftReport{
		BaselineScan:               baseline,
		CurrentScan:                current,
		ChangedComponents:          make([]ComponentChange, 0),
		NewThreats:                 make([]*models.Threat, 0),
		RemovedThreats:             make([]*models.Threat, 0),
		RemovedMitigations:         make([]string, 0),
		NewTrustBoundaryViolations: make([]string, 0),
		NewUncontrolledFlows:       make([]scanner.DataFlow, 0),
		ComparedAt:                 time.Now(),
	}
	
	// Calculate drift score
	report.DriftScore = dd.calculateDriftScore(current, baseline, report)
	
	// Determine trend
	report.TrendDirection = dd.determineTrend(current, baseline)
	
	// Analyze component changes
	report.ChangedComponents = dd.analyzeComponentChanges(current, baseline)
	
	return report
}

// calculateDriftScore calculates the drift score (0-100)
func (dd *DriftDetector) calculateDriftScore(current, baseline *scan.ScanResult, report *DriftReport) int {
	score := 0
	
	// 1. New threats
	baselineThreatMap := make(map[string]*models.Threat)
	for _, t := range baseline.Threats {
		baselineThreatMap[t.Title] = t
	}
	
	for _, t := range current.Threats {
		if _, exists := baselineThreatMap[t.Title]; !exists {
			// New threat
			report.NewThreats = append(report.NewThreats, t)
			
			// Score based on severity
			switch t.Severity {
			case models.SeverityCritical:
				score += 20
			case models.SeverityHigh:
				score += 10
			case models.SeverityMedium:
				score += 5
			default:
				score += 2
			}
		}
	}
	
	// 2. Removed threats (good!) - negative score
	currentThreatMap := make(map[string]*models.Threat)
	for _, t := range current.Threats {
		currentThreatMap[t.Title] = t
	}
	
	for _, t := range baseline.Threats {
		if _, exists := currentThreatMap[t.Title]; !exists {
			report.RemovedThreats = append(report.RemovedThreats, t)
			// Reducing threats is good
			score -= 5
		}
	}
	
	// 3. Removed mitigations (bad!)
	// Check if sensitive assets lost protections (became exposed)
	for _, baselineAsset := range baseline.Assets {
		if baselineAsset.Sensitive && !baselineAsset.Exposed {
			// Find corresponding asset in current
			currentAsset := findAssetByName(current.Assets, baselineAsset.Name)
			if currentAsset != nil {
				// Check if it became exposed (lost protection)
				if currentAsset.Exposed {
					report.RemovedMitigations = append(report.RemovedMitigations, 
						fmt.Sprintf("%s became exposed (was protected)", baselineAsset.Name))
					score += 15
				}
			}
		}
	}
	
	// 4. New trust boundary violations
	// Check for new exposed sensitive assets
	for _, currentAsset := range current.Assets {
		if currentAsset.Exposed && currentAsset.Sensitive {
			baselineAsset := findAssetByName(baseline.Assets, currentAsset.Name)
			if baselineAsset == nil || !baselineAsset.Exposed {
				report.NewTrustBoundaryViolations = append(report.NewTrustBoundaryViolations,
					fmt.Sprintf("%s became exposed", currentAsset.Name))
				score += 25
			}
		}
	}
	
	// 5. New data flows to sensitive assets
	// Check for new flows to sensitive assets
	for _, flow := range current.DataFlows {
		if flow.Sensitive {
			// Check if this flow is new
			if !dataFlowExists(baseline.DataFlows, flow) {
				report.NewUncontrolledFlows = append(report.NewUncontrolledFlows, flow)
				score += 20
			}
		}
	}
	
	// 6. Risk score delta
	riskDelta := current.Stats.MaxRiskScore - baseline.Stats.MaxRiskScore
	if riskDelta > 0 {
		// Risk increased
		score += int(riskDelta * 10) // Scale to 0-10 range
	}
	
	// Cap at 100
	if score > 100 {
		return 100
	}
	
	// Floor at 0
	if score < 0 {
		return 0
	}
	
	return score
}

// determineTrend determines if security posture is improving, stable, or degrading
func (dd *DriftDetector) determineTrend(current, baseline *scan.ScanResult) string {
	// Compare overall risk scores
	riskDelta := current.Stats.MaxRiskScore - baseline.Stats.MaxRiskScore
	
	// Compare threat counts
	criticalDelta := current.Stats.CriticalThreats - baseline.Stats.CriticalThreats
	highDelta := current.Stats.HighThreats - baseline.Stats.HighThreats
	
	// Determine trend
	if riskDelta > 0.1 || criticalDelta > 0 || highDelta > 2 {
		return "degrading"
	} else if riskDelta < -0.1 || criticalDelta < 0 || highDelta < -2 {
		return "improving"
	} else {
		return "stable"
	}
}

// analyzeComponentChanges identifies which system components changed
func (dd *DriftDetector) analyzeComponentChanges(current, baseline *scan.ScanResult) []ComponentChange {
	changes := make([]ComponentChange, 0)
	
	// Track assets by name
	baselineAssetMap := make(map[string]scanner.Asset)
	for _, a := range baseline.Assets {
		baselineAssetMap[a.Name] = a
	}
	
	currentAssetMap := make(map[string]scanner.Asset)
	for _, a := range current.Assets {
		currentAssetMap[a.Name] = a
	}
	
	// Find added assets
	for name, asset := range currentAssetMap {
		if _, exists := baselineAssetMap[name]; !exists {
			changes = append(changes, ComponentChange{
				ComponentName: name,
				ChangeType:    "added",
				Changes:       []string{fmt.Sprintf("New %s asset added", asset.Type)},
				RiskDelta:     0.1, // New component = slight risk increase
			})
		}
	}
	
	// Find removed assets
	for name, asset := range baselineAssetMap {
		if _, exists := currentAssetMap[name]; !exists {
			changes = append(changes, ComponentChange{
				ComponentName: name,
				ChangeType:    "removed",
				Changes:       []string{fmt.Sprintf("%s asset removed", asset.Type)},
				RiskDelta:     -0.05, // Removed component = slight risk decrease
			})
		}
	}
	
	// Find modified assets
	for name, currentAsset := range currentAssetMap {
		if baselineAsset, exists := baselineAssetMap[name]; exists {
			assetChanges := make([]string, 0)
			riskDelta := 0.0
			
			// Check for exposure changes
			if currentAsset.Exposed != baselineAsset.Exposed {
				if currentAsset.Exposed {
					assetChanges = append(assetChanges, "Became exposed to external access")
					riskDelta += 0.3
				} else {
					assetChanges = append(assetChanges, "No longer exposed externally")
					riskDelta -= 0.2
				}
			}
			
			// Check for sensitivity changes
			if currentAsset.Sensitive != baselineAsset.Sensitive {
				if currentAsset.Sensitive {
					assetChanges = append(assetChanges, "Now handles sensitive data")
					riskDelta += 0.2
				} else {
					assetChanges = append(assetChanges, "No longer handles sensitive data")
					riskDelta -= 0.1
				}
			}
			
			if len(assetChanges) > 0 {
				changes = append(changes, ComponentChange{
					ComponentName: name,
					ChangeType:    "modified",
					Changes:       assetChanges,
					RiskDelta:     riskDelta,
				})
			}
		}
	}
	
	return changes
}

// Helper functions

func findAssetByName(assets []scanner.Asset, name string) *scanner.Asset {
	for i := range assets {
		if assets[i].Name == name {
			return &assets[i]
		}
	}
	return nil
}

func dataFlowExists(flows []scanner.DataFlow, target scanner.DataFlow) bool {
	for _, flow := range flows {
		// Compare by source/destination file and data type
		if flow.Source.File == target.Source.File && 
		   flow.Destination.File == target.Destination.File && 
		   flow.DataType == target.DataType {
			return true
		}
	}
	return false
}

// GetDriftSeverity returns a human-readable drift severity
func GetDriftSeverity(score int) string {
	if score >= 70 {
		return "Critical"
	} else if score >= 50 {
		return "High"
	} else if score >= 30 {
		return "Medium"
	} else if score >= 10 {
		return "Low"
	} else {
		return "Minimal"
	}
}

// GetDriftEmoji returns an emoji for drift severity
func GetDriftEmoji(score int) string {
	if score >= 70 {
		return "🔴"
	} else if score >= 50 {
		return "🟠"
	} else if score >= 30 {
		return "🟡"
	} else if score >= 10 {
		return "🟢"
	} else {
		return "✅"
	}
}

// PrintDriftReport prints a user-friendly drift report
func PrintDriftReport(report *DriftReport) {
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════")
	fmt.Println("           TITO Drift Detection Report")
	fmt.Println("═══════════════════════════════════════════════")
	fmt.Println()
	
	// Overall drift score
	emoji := GetDriftEmoji(report.DriftScore)
	severity := GetDriftSeverity(report.DriftScore)
	fmt.Printf("%s Drift Score: %d/100 (%s)\n", emoji, report.DriftScore, severity)
	fmt.Println()
	
	// Trend direction
	trendEmoji := map[string]string{
		"improving":  "📈",
		"stable":     "➡️",
		"degrading":  "📉",
	}
	fmt.Printf("%s Security Posture: %s\n", trendEmoji[report.TrendDirection], report.TrendDirection)
	fmt.Println()
	
	// Baseline vs Current
	fmt.Println("📊 Comparison:")
	fmt.Printf("  Baseline: %s (scanned %s)\n", 
		report.BaselineScan.Repository.Branch, 
		report.BaselineScan.Timestamp.Format("2006-01-02 15:04"))
	fmt.Printf("  Current:  %s (scanned %s)\n", 
		report.CurrentScan.Repository.Branch, 
		report.CurrentScan.Timestamp.Format("2006-01-02 15:04"))
	fmt.Println()
	
	// New threats
	if len(report.NewThreats) > 0 {
		fmt.Printf("🆕 New Threats: %d\n", len(report.NewThreats))
		for i, threat := range report.NewThreats {
			if i >= 5 {
				fmt.Printf("     ... and %d more\n", len(report.NewThreats)-5)
				break
			}
			fmt.Printf("     [%s] %s\n", threat.Severity, threat.Title)
		}
		fmt.Println()
	}
	
	// Removed threats
	if len(report.RemovedThreats) > 0 {
		fmt.Printf("✅ Resolved Threats: %d\n", len(report.RemovedThreats))
		for i, threat := range report.RemovedThreats {
			if i >= 3 {
				fmt.Printf("     ... and %d more\n", len(report.RemovedThreats)-3)
				break
			}
			fmt.Printf("     [%s] %s\n", threat.Severity, threat.Title)
		}
		fmt.Println()
	}
	
	// Removed mitigations
	if len(report.RemovedMitigations) > 0 {
		fmt.Printf("⚠️  Removed Mitigations: %d\n", len(report.RemovedMitigations))
		for _, mitigation := range report.RemovedMitigations {
			fmt.Printf("     • %s\n", mitigation)
		}
		fmt.Println()
	}
	
	// Trust boundary violations
	if len(report.NewTrustBoundaryViolations) > 0 {
		fmt.Printf("🚨 New Trust Boundary Violations: %d\n", len(report.NewTrustBoundaryViolations))
		for _, violation := range report.NewTrustBoundaryViolations {
			fmt.Printf("     • %s\n", violation)
		}
		fmt.Println()
	}
	
	// Component changes
	if len(report.ChangedComponents) > 0 {
		fmt.Printf("🔧 Changed Components: %d\n", len(report.ChangedComponents))
		for i, change := range report.ChangedComponents {
			if i >= 5 {
				fmt.Printf("     ... and %d more\n", len(report.ChangedComponents)-5)
				break
			}
			deltaStr := ""
			if change.RiskDelta > 0 {
				deltaStr = fmt.Sprintf(" (+%.1f risk)", change.RiskDelta)
			} else if change.RiskDelta < 0 {
				deltaStr = fmt.Sprintf(" (%.1f risk)", change.RiskDelta)
			}
			fmt.Printf("     %s [%s]%s\n", change.ComponentName, change.ChangeType, deltaStr)
			for _, desc := range change.Changes {
				fmt.Printf("       → %s\n", desc)
			}
		}
		fmt.Println()
	}
	
	// Recommendation
	fmt.Println("💡 Recommendation:")
	if report.DriftScore >= 50 {
		fmt.Println("   Security posture has degraded significantly.")
		fmt.Println("   Review and address new threats before deployment.")
	} else if report.DriftScore >= 20 {
		fmt.Println("   Moderate drift detected. Review changes carefully.")
	} else {
		fmt.Println("   Drift is within acceptable range. Keep monitoring.")
	}
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════")
	fmt.Println()
}
