package scan

import (
	"os"
	"testing"
	"time"

	"github.com/Leathal1/TITO/v2/pkg/attackpath"
	"github.com/Leathal1/TITO/v2/pkg/mapper"
	"github.com/Leathal1/TITO/v2/pkg/models"
	"github.com/Leathal1/TITO/v2/pkg/scanner"
)

func TestNewScanResult(t *testing.T) {
	result := NewScanResult()

	if result.Version != "1.0" {
		t.Errorf("Expected version 1.0, got %s", result.Version)
	}

	if result.Assets == nil {
		t.Error("Assets slice should be initialized")
	}
	if result.DataFlows == nil {
		t.Error("DataFlows slice should be initialized")
	}
	if result.Threats == nil {
		t.Error("Threats slice should be initialized")
	}
}

func TestCalculateStats(t *testing.T) {
	result := NewScanResult()

	// Add test data
	result.Assets = []scanner.Asset{
		{ID: "1", Type: scanner.AssetAPI, Name: "Test API"},
		{ID: "2", Type: scanner.AssetDatabase, Name: "Test DB"},
	}

	result.DataFlows = []scanner.DataFlow{
		{ID: "flow1", DataType: "user_data"},
	}

	result.Threats = []*models.Threat{
		{
			ID:       "threat1",
			Title:    "SQL Injection",
			Severity: models.SeverityCritical,
		},
		{
			ID:       "threat2",
			Title:    "XSS",
			Severity: models.SeverityHigh,
		},
		{
			ID:       "threat3",
			Title:    "Info Disclosure",
			Severity: models.SeverityMedium,
		},
	}

	result.MappedThreats = []mapper.MappedThreat{
		{RiskScore: 0.8},
		{RiskScore: 0.6},
		{RiskScore: 0.4},
	}

	result.AttackPaths = []attackpath.AttackPath{
		{CompositeRisk: 7.5},
	}

	result.CalculateStats()

	if result.Stats.TotalAssets != 2 {
		t.Errorf("Expected 2 assets, got %d", result.Stats.TotalAssets)
	}

	if result.Stats.TotalDataFlows != 1 {
		t.Errorf("Expected 1 data flow, got %d", result.Stats.TotalDataFlows)
	}

	if result.Stats.TotalThreats != 3 {
		t.Errorf("Expected 3 threats, got %d", result.Stats.TotalThreats)
	}

	if result.Stats.CriticalThreats != 1 {
		t.Errorf("Expected 1 critical threat, got %d", result.Stats.CriticalThreats)
	}

	if result.Stats.HighThreats != 1 {
		t.Errorf("Expected 1 high threat, got %d", result.Stats.HighThreats)
	}

	if result.Stats.TotalAttackPaths != 1 {
		t.Errorf("Expected 1 attack path, got %d", result.Stats.TotalAttackPaths)
	}

	// Max risk should be from mapped threats (0.8)
	if result.Stats.MaxRiskScore < 0.79 || result.Stats.MaxRiskScore > 0.81 {
		t.Errorf("Expected max risk ~0.80, got %.2f", result.Stats.MaxRiskScore)
	}

	// Average should be (0.8 + 0.6 + 0.4 + 0.75) / 4 = 0.6375
	expectedAvg := (0.8 + 0.6 + 0.4 + 0.75) / 4
	if result.Stats.AvgRiskScore < expectedAvg-0.01 || result.Stats.AvgRiskScore > expectedAvg+0.01 {
		t.Errorf("Expected avg risk ~%.2f, got %.2f", expectedAvg, result.Stats.AvgRiskScore)
	}
}

func TestSaveAndLoadResult(t *testing.T) {
	// Create a test result
	result := NewScanResult()
	result.Repository = RepositoryInfo{
		URL:       "https://github.com/test/repo",
		Branch:    "main",
		Language:  "go",
		Framework: "gin",
		CommitSHA: "abc123",
	}

	result.Assets = []scanner.Asset{
		{
			ID:       "asset1",
			Type:     scanner.AssetAPI,
			Name:     "POST /api/users",
			Location: scanner.Location{File: "main.go", Line: 42},
			Sensitive: true,
			Exposed:  true,
		},
	}

	result.Threats = []*models.Threat{
		{
			ID:       "threat1",
			Title:    "SQL Injection",
			Severity: models.SeverityCritical,
			Description: "Unvalidated user input in SQL query",
			DiscoveredAt: time.Now(),
		},
	}

	// Save to temp file
	tmpFile := "/tmp/test-scan-result.tito.json"
	defer os.Remove(tmpFile)

	err := SaveResult(result, tmpFile)
	if err != nil {
		t.Fatalf("Failed to save result: %v", err)
	}

	// Check file exists
	if _, err := os.Stat(tmpFile); os.IsNotExist(err) {
		t.Fatal("Result file was not created")
	}

	// Load it back
	loaded, err := LoadResult(tmpFile)
	if err != nil {
		t.Fatalf("Failed to load result: %v", err)
	}

	// Verify data
	if loaded.Version != result.Version {
		t.Errorf("Version mismatch: expected %s, got %s", result.Version, loaded.Version)
	}

	if loaded.Repository.URL != result.Repository.URL {
		t.Errorf("Repository URL mismatch: expected %s, got %s", result.Repository.URL, loaded.Repository.URL)
	}

	if len(loaded.Assets) != len(result.Assets) {
		t.Errorf("Assets count mismatch: expected %d, got %d", len(result.Assets), len(loaded.Assets))
	}

	if len(loaded.Threats) != len(result.Threats) {
		t.Errorf("Threats count mismatch: expected %d, got %d", len(result.Threats), len(loaded.Threats))
	}

	// Verify stats were calculated
	if loaded.Stats.TotalAssets != 1 {
		t.Errorf("Expected stats to be calculated, got %d assets", loaded.Stats.TotalAssets)
	}
}

func TestLoadNonexistentFile(t *testing.T) {
	_, err := LoadResult("/tmp/nonexistent-file.tito.json")
	if err == nil {
		t.Error("Expected error when loading nonexistent file")
	}
}

func TestLoadInvalidJSON(t *testing.T) {
	tmpFile := "/tmp/invalid.tito.json"
	defer os.Remove(tmpFile)

	// Write invalid JSON
	err := os.WriteFile(tmpFile, []byte("not valid json {"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	_, err = LoadResult(tmpFile)
	if err == nil {
		t.Error("Expected error when loading invalid JSON")
	}
}
