package collectors

import (
	"context"
	"testing"

	"github.com/Leathal1/TITO/v2/pkg/models"
	"github.com/Leathal1/TITO/v2/pkg/stridelm"
)

func TestNewNVDCollector(t *testing.T) {
	apiKey := "test-api-key"
	daysBack := 7

	collector := NewNVDCollector(apiKey, daysBack)

	if collector == nil {
		t.Fatal("NewNVDCollector returned nil")
	}

	if collector.apiKey != apiKey {
		t.Errorf("expected API key %s, got %s", apiKey, collector.apiKey)
	}

	if collector.daysBack != daysBack {
		t.Errorf("expected daysBack %d, got %d", daysBack, collector.daysBack)
	}

	if collector.Name() != "NVD" {
		t.Errorf("expected name 'NVD', got %s", collector.Name())
	}
}

func TestNVDCollector_Interval(t *testing.T) {
	collector := NewNVDCollector("test-key", 7)

	interval := collector.Interval()
	expectedHours := 6

	if interval.Hours() != float64(expectedHours) {
		t.Errorf("expected interval %d hours, got %v", expectedHours, interval)
	}
}

func TestNVDCollector_ShouldRun(t *testing.T) {
	collector := NewNVDCollector("test-key", 7)

	// Should run on first call (lastRun is zero)
	if !collector.ShouldRun() {
		t.Error("should run when lastRun is zero")
	}

	// Record a run
	collector.RecordRun()

	// Should not run immediately after
	if collector.ShouldRun() {
		t.Error("should not run immediately after recording run")
	}
}

func TestNVDCollector_Collect(t *testing.T) {
	collector := NewNVDCollector("test-key", 7)
	ctx := context.Background()

	threats, err := collector.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	// Mock data should return at least some threats
	if len(threats) == 0 {
		t.Error("expected at least some mock threats")
	}

	// Validate threat structure
	for i, threat := range threats {
		if threat.ID == "" {
			t.Errorf("threat %d has empty ID", i)
		}

		if threat.Title == "" {
			t.Errorf("threat %d has empty title", i)
		}

		if threat.Severity == "" {
			t.Errorf("threat %d has empty severity", i)
		}

		if threat.StrideProfile == nil {
			t.Errorf("threat %d has nil STRIDE profile", i)
		}

		if len(threat.CVEIDs) == 0 {
			t.Errorf("threat %d has no CVE IDs", i)
		}

		if len(threat.Indicators) == 0 {
			t.Errorf("threat %d has no indicators", i)
		}
	}
}

func TestNVDCollector_ParseCVE(t *testing.T) {
	collector := NewNVDCollector("test-key", 7)

	cveData := CVEData{
		CVE: CVEInfo{
			ID: "CVE-2024-TEST",
			Descriptions: []Description{
				{Lang: "en", Value: "SQL injection vulnerability"},
			},
		},
		Metrics: Metrics{
			CVSSMetricV31: []CVSSMetric{
				{
					CVSSData: CVSSData{
						BaseScore:    9.8,
						BaseSeverity: "CRITICAL",
						VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					},
				},
			},
		},
	}

	threat, err := collector.parseCVE(cveData)
	if err != nil {
		t.Fatalf("parseCVE failed: %v", err)
	}

	if threat == nil {
		t.Fatal("parseCVE returned nil threat")
	}

	// Validate parsed data
	if !contains(threat.Title, "CVE-2024-TEST") {
		t.Errorf("threat title should contain CVE ID, got %s", threat.Title)
	}

	if threat.Severity != models.SeverityCritical {
		t.Errorf("expected severity Critical for score 9.8, got %s", threat.Severity)
	}

	if len(threat.CVEIDs) != 1 || threat.CVEIDs[0] != "CVE-2024-TEST" {
		t.Errorf("expected CVE ID CVE-2024-TEST, got %v", threat.CVEIDs)
	}

	if threat.Description != "SQL injection vulnerability" {
		t.Errorf("expected description 'SQL injection vulnerability', got %s", threat.Description)
	}
}

func TestNVDCollector_MapSeverity(t *testing.T) {
	collector := NewNVDCollector("test-key", 7)

	tests := []struct {
		input    string
		expected models.ThreatSeverity
	}{
		{"critical", models.SeverityCritical},
		{"high", models.SeverityHigh},
		{"medium", models.SeverityMedium},
		{"low", models.SeverityLow},
		{"none", models.SeverityInfo},
		{"unknown", models.SeverityMedium}, // default
	}

	for _, tt := range tests {
		result := collector.mapSeverity(tt.input)
		if result != tt.expected {
			t.Errorf("mapSeverity(%q) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}

func TestNVDCollector_ExtractCWEIDs(t *testing.T) {
	collector := NewNVDCollector("test-key", 7)

	weaknesses := []Weakness{
		{
			Description: []Description{
				{Value: "CWE-89"},
			},
		},
		{
			Description: []Description{
				{Value: "CWE-287"},
			},
		},
	}

	cweIDs := collector.extractCWEIDs(weaknesses)

	if len(cweIDs) != 2 {
		t.Errorf("expected 2 CWE IDs, got %d", len(cweIDs))
	}

	// Check that IDs were extracted correctly
	expectedIDs := map[int]bool{89: true, 287: true}
	for _, id := range cweIDs {
		if !expectedIDs[id] {
			t.Errorf("unexpected CWE ID: %d", id)
		}
	}
}

func TestNVDCollector_ParseCVSSVector(t *testing.T) {
	collector := NewNVDCollector("test-key", 7)

	vectorString := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	context := collector.parseCVSSVector(vectorString, "CVE-2024-TEST")

	// Network attack vector
	if context.ExposureLevel != "internet" {
		t.Errorf("expected ExposureLevel 'internet' for AV:N, got %s", context.ExposureLevel)
	}

	// Low attack complexity
	if context.AttackComplexity != "low" {
		t.Errorf("expected AttackComplexity 'low' for AC:L, got %s", context.AttackComplexity)
	}

	// No privileges required
	if context.PrivilegesRequired != "none" {
		t.Errorf("expected PrivilegesRequired 'none' for PR:N, got %s", context.PrivilegesRequired)
	}

	// No user interaction
	if context.UserInteractionRequired {
		t.Error("expected UserInteractionRequired false for UI:N")
	}

	// Should affect known assets (network accessible)
	if !context.AffectsKnownAssets {
		t.Error("expected AffectsKnownAssets true for network accessible threat")
	}
}

func TestNVDCollector_ParseCVSSVector_Adjacent(t *testing.T) {
	collector := NewNVDCollector("test-key", 7)

	vectorString := "CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N"
	context := collector.parseCVSSVector(vectorString, "CVE-2024-TEST")

	// Adjacent network
	if context.ExposureLevel != "internal" {
		t.Errorf("expected ExposureLevel 'internal' for AV:A, got %s", context.ExposureLevel)
	}

	// High attack complexity
	if context.AttackComplexity != "high" {
		t.Errorf("expected AttackComplexity 'high' for AC:H, got %s", context.AttackComplexity)
	}

	// Low privileges required
	if context.PrivilegesRequired != "low" {
		t.Errorf("expected PrivilegesRequired 'low' for PR:L, got %s", context.PrivilegesRequired)
	}

	// User interaction required
	if !context.UserInteractionRequired {
		t.Error("expected UserInteractionRequired true for UI:R")
	}
}

func TestNVDCollector_GenerateRecommendations(t *testing.T) {
	collector := NewNVDCollector("test-key", 7)

	profile := &stridelm.Profile{
		PrimaryCategory: stridelm.Tampering,
	}

	// Critical severity
	recommendations := collector.generateRecommendations(profile, models.SeverityCritical, "CVE-2024-TEST")

	if len(recommendations) == 0 {
		t.Error("expected recommendations for critical threat")
	}

	// Should include urgency for critical
	hasUrgency := false
	for _, rec := range recommendations {
		if contains(rec, "URGENT") || contains(rec, "immediately") {
			hasUrgency = true
			break
		}
	}
	if !hasUrgency {
		t.Error("expected urgent recommendations for critical severity")
	}

	// Should include CVE reference
	hasCVERef := false
	for _, rec := range recommendations {
		if contains(rec, "CVE-2024-TEST") {
			hasCVERef = true
			break
		}
	}
	if !hasCVERef {
		t.Error("expected CVE reference in recommendations")
	}
}

func TestNVDCollector_Truncate(t *testing.T) {
	collector := NewNVDCollector("test-key", 7)

	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"short", 10, "short"},
		{"this is a very long string that should be truncated", 20, "this is a very long ..."},
		{"exactly 10", 10, "exactly 10"},
	}

	for _, tt := range tests {
		result := collector.truncate(tt.input, tt.maxLen)
		if len(result) > tt.maxLen+3 { // +3 for "..."
			t.Errorf("truncate(%q, %d) resulted in string longer than max: %q", tt.input, tt.maxLen, result)
		}
	}
}

func TestNVDCollector_GetMockCVEs(t *testing.T) {
	collector := NewNVDCollector("test-key", 7)

	mockCVEs := collector.getMockCVEs()

	if len(mockCVEs) == 0 {
		t.Error("expected at least some mock CVEs")
	}

	// Validate mock data structure
	for i, cve := range mockCVEs {
		if cve.CVE.ID == "" {
			t.Errorf("mock CVE %d has empty ID", i)
		}

		if len(cve.CVE.Descriptions) == 0 {
			t.Errorf("mock CVE %d has no descriptions", i)
		}

		if len(cve.Metrics.CVSSMetricV31) == 0 {
			t.Errorf("mock CVE %d has no CVSS metrics", i)
		}
	}
}

func TestNVDCollector_ErrorHandling(t *testing.T) {
	collector := NewNVDCollector("test-key", 7)

	// Test with invalid CVE data (empty)
	cveData := CVEData{}
	
	threat, err := collector.parseCVE(cveData)
	
	// Should not error, but create a basic threat
	if err != nil {
		t.Errorf("parseCVE should handle empty data gracefully, got error: %v", err)
	}

	if threat == nil {
		t.Error("parseCVE should return a threat even with empty data")
	}
}

func TestBaseCollector_Integration(t *testing.T) {
	collector := NewNVDCollector("test-key", 7)

	// Test Name
	if collector.Name() != "NVD" {
		t.Errorf("expected name 'NVD', got %s", collector.Name())
	}

	// Test Interval
	interval := collector.Interval()
	if interval.Hours() != 6 {
		t.Errorf("expected 6 hour interval, got %v", interval)
	}

	// Test ShouldRun
	if !collector.ShouldRun() {
		t.Error("should run when lastRun is zero")
	}
}

// Helper function
func contains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}

	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			if s[i+j] != substr[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
