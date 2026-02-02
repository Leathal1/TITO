package diff

import (
	"testing"

	"github.com/Leathal1/TITO/v2/pkg/attackpath"
	"github.com/Leathal1/TITO/v2/pkg/mapper"
	"github.com/Leathal1/TITO/v2/pkg/models"
	"github.com/Leathal1/TITO/v2/pkg/scan"
	"github.com/Leathal1/TITO/v2/pkg/scanner"
)

func TestComputeDiff_EmptyScans(t *testing.T) {
	base := scan.NewScanResult()
	head := scan.NewScanResult()

	diff := ComputeDiff(base, head)

	if diff.Summary.TotalChanges != 0 {
		t.Errorf("Expected 0 changes for empty scans, got %d", diff.Summary.TotalChanges)
	}

	if diff.RiskDelta.RiskDirection != "unchanged" {
		t.Errorf("Expected unchanged risk, got %s", diff.RiskDelta.RiskDirection)
	}
}

func TestComputeDiff_IdenticalScans(t *testing.T) {
	base := createTestScanResult()
	head := createTestScanResult()

	diff := ComputeDiff(base, head)

	if len(diff.AddedAssets) != 0 {
		t.Errorf("Expected 0 added assets, got %d", len(diff.AddedAssets))
	}

	if len(diff.RemovedAssets) != 0 {
		t.Errorf("Expected 0 removed assets, got %d", len(diff.RemovedAssets))
	}

	if len(diff.AddedThreats) != 0 {
		t.Errorf("Expected 0 added threats, got %d", len(diff.AddedThreats))
	}

	if diff.Summary.TotalChanges != 0 {
		t.Errorf("Expected 0 total changes, got %d", diff.Summary.TotalChanges)
	}
}

func TestComputeDiff_AddedAssets(t *testing.T) {
	base := scan.NewScanResult()
	head := scan.NewScanResult()

	head.Assets = []scanner.Asset{
		{
			ID:   "asset1",
			Type: scanner.AssetAPI,
			Name: "POST /api/users",
			Location: scanner.Location{
				File: "main.go",
				Line: 42,
			},
			Exposed:   true,
			Sensitive: true,
		},
		{
			ID:   "asset2",
			Type: scanner.AssetDatabase,
			Name: "Database Query",
			Location: scanner.Location{
				File: "db.go",
				Line: 10,
			},
		},
	}

	diff := ComputeDiff(base, head)

	if len(diff.AddedAssets) != 2 {
		t.Errorf("Expected 2 added assets, got %d", len(diff.AddedAssets))
	}

	if len(diff.RemovedAssets) != 0 {
		t.Errorf("Expected 0 removed assets, got %d", len(diff.RemovedAssets))
	}

	if diff.Summary.TotalChanges != 2 {
		t.Errorf("Expected 2 total changes, got %d", diff.Summary.TotalChanges)
	}
}

func TestComputeDiff_AddedThreats(t *testing.T) {
	base := scan.NewScanResult()
	head := scan.NewScanResult()

	head.Threats = []*models.Threat{
		{
			ID:       "threat1",
			Title:    "SQL Injection",
			Severity: models.SeverityCritical,
		},
		{
			ID:       "threat2",
			Title:    "XSS Vulnerability",
			Severity: models.SeverityHigh,
		},
	}

	head.Stats.TotalThreats = 2
	head.Stats.CriticalThreats = 1
	head.Stats.HighThreats = 1

	diff := ComputeDiff(base, head)

	if len(diff.AddedThreats) != 2 {
		t.Errorf("Expected 2 added threats, got %d", len(diff.AddedThreats))
	}

	if diff.Summary.NewHighSeverity != 2 {
		t.Errorf("Expected 2 new high severity threats, got %d", diff.Summary.NewHighSeverity)
	}

	// Verify threats are sorted by severity (critical first)
	if diff.AddedThreats[0].Severity != models.SeverityCritical {
		t.Errorf("Expected first threat to be critical, got %s", diff.AddedThreats[0].Severity)
	}
}

func TestComputeDiff_RemovedThreats(t *testing.T) {
	base := scan.NewScanResult()
	head := scan.NewScanResult()

	base.Threats = []*models.Threat{
		{
			ID:       "threat1",
			Title:    "SQL Injection",
			Severity: models.SeverityCritical,
		},
	}

	diff := ComputeDiff(base, head)

	if len(diff.RemovedThreats) != 1 {
		t.Errorf("Expected 1 removed threat, got %d", len(diff.RemovedThreats))
	}

	if diff.Summary.ResolvedThreats != 1 {
		t.Errorf("Expected 1 resolved threat, got %d", diff.Summary.ResolvedThreats)
	}
}

func TestComputeDiff_ModifiedAssets(t *testing.T) {
	base := scan.NewScanResult()
	head := scan.NewScanResult()

	// Same asset, but different exposure
	baseAsset := scanner.Asset{
		ID:        "asset1",
		Type:      scanner.AssetAPI,
		Name:      "POST /api/users",
		Location:  scanner.Location{File: "main.go", Line: 42},
		Exposed:   false,
		Sensitive: false,
	}

	headAsset := scanner.Asset{
		ID:        "asset1",
		Type:      scanner.AssetAPI,
		Name:      "POST /api/users",
		Location:  scanner.Location{File: "main.go", Line: 42},
		Exposed:   true, // Now exposed!
		Sensitive: true, // Now sensitive!
	}

	base.Assets = []scanner.Asset{baseAsset}
	head.Assets = []scanner.Asset{headAsset}

	diff := ComputeDiff(base, head)

	if len(diff.ModifiedAssets) != 1 {
		t.Errorf("Expected 1 modified asset, got %d", len(diff.ModifiedAssets))
	}

	if len(diff.ModifiedAssets[0].Changes) != 2 {
		t.Errorf("Expected 2 changes, got %d", len(diff.ModifiedAssets[0].Changes))
	}
}

func TestComputeDiff_DataFlows(t *testing.T) {
	base := scan.NewScanResult()
	head := scan.NewScanResult()

	head.DataFlows = []scanner.DataFlow{
		{
			ID:       "flow1",
			Source:   scanner.Location{File: "api.go", Line: 10},
			Destination: scanner.Location{File: "db.go", Line: 20},
			DataType: "user_data",
			Sensitive: true,
		},
	}

	diff := ComputeDiff(base, head)

	if len(diff.AddedFlows) != 1 {
		t.Errorf("Expected 1 added flow, got %d", len(diff.AddedFlows))
	}
}

func TestComputeDiff_AttackPaths(t *testing.T) {
	base := scan.NewScanResult()
	head := scan.NewScanResult()

	head.AttackPaths = []attackpath.AttackPath{
		{
			ID:            "path1",
			EntryPoint:    "API Gateway",
			Target:        "Database",
			CompositeRisk: 7.5,
		},
	}

	diff := ComputeDiff(base, head)

	if len(diff.AddedPaths) != 1 {
		t.Errorf("Expected 1 added path, got %d", len(diff.AddedPaths))
	}

	if diff.Summary.NewAttackPaths != 1 {
		t.Errorf("Expected 1 new attack path in summary, got %d", diff.Summary.NewAttackPaths)
	}
}

func TestComputeDiff_Dependencies(t *testing.T) {
	base := scan.NewScanResult()
	head := scan.NewScanResult()

	base.Dependencies = []scanner.Dependency{
		{Name: "example-lib", Version: "1.0.0", Type: "direct"},
		{Name: "old-lib", Version: "0.5.0", Type: "direct"},
	}

	head.Dependencies = []scanner.Dependency{
		{Name: "example-lib", Version: "1.2.0", Type: "direct"}, // Updated
		{Name: "new-lib", Version: "2.0.0", Type: "direct"},     // Added
		// old-lib removed
	}

	diff := ComputeDiff(base, head)

	if len(diff.UpdatedDeps) != 1 {
		t.Errorf("Expected 1 updated dependency, got %d", len(diff.UpdatedDeps))
	}

	if diff.UpdatedDeps[0].Name != "example-lib" {
		t.Errorf("Expected example-lib to be updated")
	}

	if len(diff.AddedDeps) != 1 {
		t.Errorf("Expected 1 added dependency, got %d", len(diff.AddedDeps))
	}

	if len(diff.RemovedDeps) != 1 {
		t.Errorf("Expected 1 removed dependency, got %d", len(diff.RemovedDeps))
	}
}

func TestComputeDiff_RiskDelta(t *testing.T) {
	base := scan.NewScanResult()
	head := scan.NewScanResult()

	base.Stats.MaxRiskScore = 0.5
	base.Stats.AvgRiskScore = 0.3

	head.Stats.MaxRiskScore = 0.8
	head.Stats.AvgRiskScore = 0.6

	diff := ComputeDiff(base, head)

	if diff.RiskDelta.BaseMaxRisk != 0.5 {
		t.Errorf("Expected base max risk 0.5, got %.2f", diff.RiskDelta.BaseMaxRisk)
	}

	if diff.RiskDelta.HeadMaxRisk != 0.8 {
		t.Errorf("Expected head max risk 0.8, got %.2f", diff.RiskDelta.HeadMaxRisk)
	}

	if diff.RiskDelta.RiskDirection != "increased" {
		t.Errorf("Expected risk direction 'increased', got %s", diff.RiskDelta.RiskDirection)
	}
}

func TestDetermineVerdict_Pass(t *testing.T) {
	diff := &DiffResult{
		RiskDelta: RiskDelta{
			BaseMaxRisk: 0.5,
			HeadMaxRisk: 0.5,
			RiskDirection: "unchanged",
		},
		Summary: DiffSummary{
			TotalChanges: 0,
		},
	}

	config := DefaultVerdictConfig()
	verdict, _ := DetermineVerdict(diff, config)

	if verdict != "PASS" {
		t.Errorf("Expected PASS verdict, got %s", verdict)
	}
}

func TestDetermineVerdict_FailOnCritical(t *testing.T) {
	diff := &DiffResult{
		AddedThreats: []*models.Threat{
			{
				ID:       "threat1",
				Title:    "Critical Vulnerability",
				Severity: models.SeverityCritical,
			},
		},
		RiskDelta: RiskDelta{
			RiskDirection: "increased",
		},
	}

	config := FailOnCriticalConfig()
	verdict, reason := DetermineVerdict(diff, config)

	if verdict != "FAIL" {
		t.Errorf("Expected FAIL verdict for critical threat, got %s", verdict)
	}

	if reason == "" {
		t.Error("Expected verdict reason to be provided")
	}
}

func TestDetermineVerdict_WarnOnHigh(t *testing.T) {
	diff := &DiffResult{
		AddedThreats: []*models.Threat{
			{
				ID:       "threat1",
				Title:    "High Severity Issue",
				Severity: models.SeverityHigh,
			},
		},
		RiskDelta: RiskDelta{
			RiskDirection: "increased",
		},
		Summary: DiffSummary{
			NewHighSeverity: 1,
		},
	}

	config := FailOnCriticalConfig() // Should warn on high
	verdict, _ := DetermineVerdict(diff, config)

	if verdict != "WARN" {
		t.Errorf("Expected WARN verdict for high severity, got %s", verdict)
	}
}

func TestDetermineVerdict_PassOnResolvedThreats(t *testing.T) {
	diff := &DiffResult{
		RemovedThreats: []*models.Threat{
			{ID: "resolved1", Title: "Fixed Issue", Severity: models.SeverityHigh},
		},
		RiskDelta: RiskDelta{
			BaseMaxRisk:   0.7,
			HeadMaxRisk:   0.5,
			RiskDirection: "decreased",
		},
		Summary: DiffSummary{
			ResolvedThreats: 1,
		},
	}

	config := DefaultVerdictConfig()
	verdict, _ := DetermineVerdict(diff, config)

	if verdict != "PASS" {
		t.Errorf("Expected PASS verdict when threats resolved, got %s", verdict)
	}
}

func TestVerdictToExitCode(t *testing.T) {
	tests := []struct {
		verdict  string
		expected int
	}{
		{"PASS", 0},
		{"WARN", 1},
		{"FAIL", 2},
		{"UNKNOWN", 1},
	}

	for _, test := range tests {
		code := VerdictToExitCode(test.verdict)
		if code != test.expected {
			t.Errorf("Expected exit code %d for %s, got %d", test.expected, test.verdict, code)
		}
	}
}

// Helper function to create a test scan result
func createTestScanResult() *scan.ScanResult {
	result := scan.NewScanResult()

	result.Repository = scan.RepositoryInfo{
		URL:       "https://github.com/test/repo",
		Branch:    "main",
		Language:  "go",
		Framework: "gin",
	}

	result.Assets = []scanner.Asset{
		{
			ID:        "asset1",
			Type:      scanner.AssetAPI,
			Name:      "POST /api/users",
			Location:  scanner.Location{File: "main.go", Line: 42},
			Sensitive: true,
		},
	}

	result.Threats = []*models.Threat{
		{
			ID:       "threat1",
			Title:    "SQL Injection",
			Severity: models.SeverityHigh,
		},
	}

	result.MappedThreats = []mapper.MappedThreat{
		{RiskScore: 0.6},
	}

	result.CalculateStats()

	return result
}
