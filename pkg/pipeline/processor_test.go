package pipeline

import (
	"context"
	"testing"
	"time"

	"github.com/Leathal1/TITO/v2/pkg/models"
	"github.com/Leathal1/TITO/v2/pkg/stridelm"
)

func TestNewProcessor(t *testing.T) {
	config := ProcessorConfig{
		MinPriority: 5.0,
		MaxAgeDays:  30,
	}

	p := NewProcessor(config)
	if p == nil {
		t.Fatal("NewProcessor returned nil")
	}

	if p.config.MinPriority != 5.0 {
		t.Errorf("expected MinPriority 5.0, got %f", p.config.MinPriority)
	}

	if p.config.MaxAgeDays != 30 {
		t.Errorf("expected MaxAgeDays 30, got %d", p.config.MaxAgeDays)
	}
}

func TestProcess(t *testing.T) {
	config := ProcessorConfig{
		MinPriority: 0.0,
		MaxAgeDays:  365,
	}

	p := NewProcessor(config)
	ctx := context.Background()

	threats := []*models.Threat{
		createTestThreat("threat-1", "SQL Injection", models.SeverityCritical),
		createTestThreat("threat-2", "Auth Bypass", models.SeverityHigh),
		createTestThreat("threat-3", "Info Leak", models.SeverityMedium),
	}

	processed, err := p.Process(ctx, threats)
	if err != nil {
		t.Fatalf("Process failed: %v", err)
	}

	if len(processed) == 0 {
		t.Error("Process returned no threats")
	}

	// Check that threats were processed
	metrics := p.GetMetrics()
	if metrics.Input != 3 {
		t.Errorf("expected input count 3, got %d", metrics.Input)
	}
}

func TestNormalize(t *testing.T) {
	p := NewProcessor(ProcessorConfig{})

	// Threat with empty title
	threat := &models.Threat{
		ID:          "test-1",
		Description: "This is a test description",
		Severity:    models.SeverityHigh,
	}

	normalized := p.normalize([]*models.Threat{threat})

	if len(normalized) != 1 {
		t.Fatalf("expected 1 threat, got %d", len(normalized))
	}

	// Title should be set from description
	if normalized[0].Title == "" {
		t.Error("title should be set from description")
	}

	// Timestamps should be set
	if normalized[0].DiscoveredAt.IsZero() {
		t.Error("DiscoveredAt should be set")
	}

	if normalized[0].UpdatedAt.IsZero() {
		t.Error("UpdatedAt should be set")
	}
}

func TestNormalize_TagsLowercase(t *testing.T) {
	p := NewProcessor(ProcessorConfig{})

	threat := &models.Threat{
		ID:       "test-1",
		Title:    "Test Threat",
		Severity: models.SeverityHigh,
		Tags:     []string{"CVE", "CRITICAL", "Network"},
	}

	normalized := p.normalize([]*models.Threat{threat})

	if len(normalized) != 1 {
		t.Fatalf("expected 1 threat, got %d", len(normalized))
	}

	// Check that all tags are lowercase
	for _, tag := range normalized[0].Tags {
		if tag != toLower(tag) {
			t.Errorf("tag %s is not lowercase", tag)
		}
	}
}

func TestEnrich(t *testing.T) {
	p := NewProcessor(ProcessorConfig{})
	ctx := context.Background()

	threat := createTestThreat("test-1", "SQL Injection", models.SeverityCritical)
	threat.StrideProfile = &stridelm.Profile{
		PrimaryCategory: stridelm.Tampering,
		ConfidenceScores: map[stridelm.Category]float64{
			stridelm.Tampering: 0.9,
		},
	}

	enriched := p.enrich(ctx, []*models.Threat{threat})

	if len(enriched) != 1 {
		t.Fatalf("expected 1 threat, got %d", len(enriched))
	}

	// Check that asset relevance was checked
	// (High severity threats should affect known assets)
	if !enriched[0].Context.AffectsKnownAssets {
		t.Error("critical threat should affect known assets")
	}
}

func TestDeduplicate_ByCVE(t *testing.T) {
	p := NewProcessor(ProcessorConfig{})

	threat1 := createTestThreat("threat-1", "CVE-2024-1234", models.SeverityHigh)
	threat1.CVEIDs = []string{"CVE-2024-1234"}

	threat2 := createTestThreat("threat-2", "CVE-2024-1234 Duplicate", models.SeverityHigh)
	threat2.CVEIDs = []string{"CVE-2024-1234"}

	threats := []*models.Threat{threat1, threat2}

	deduplicated := p.deduplicate(threats)

	if len(deduplicated) != 1 {
		t.Errorf("expected 1 deduplicated threat, got %d", len(deduplicated))
	}
}

func TestDeduplicate_ByIndicator(t *testing.T) {
	p := NewProcessor(ProcessorConfig{})

	threat1 := createTestThreat("threat-1", "Malicious IP", models.SeverityMedium)
	threat1.Indicators = []models.ThreatIndicator{
		{
			Type:  models.IndicatorIPAddress,
			Value: "192.168.1.100",
		},
	}

	threat2 := createTestThreat("threat-2", "Same Malicious IP", models.SeverityMedium)
	threat2.Indicators = []models.ThreatIndicator{
		{
			Type:  models.IndicatorIPAddress,
			Value: "192.168.1.100",
		},
	}

	threats := []*models.Threat{threat1, threat2}

	deduplicated := p.deduplicate(threats)

	if len(deduplicated) != 1 {
		t.Errorf("expected 1 deduplicated threat, got %d", len(deduplicated))
	}
}

func TestPrioritize(t *testing.T) {
	p := NewProcessor(ProcessorConfig{})

	threats := []*models.Threat{
		createTestThreat("low", "Low Priority", models.SeverityLow),
		createTestThreat("critical", "Critical Priority", models.SeverityCritical),
		createTestThreat("medium", "Medium Priority", models.SeverityMedium),
	}

	prioritized := p.prioritize(threats)

	// Should be sorted by priority (highest first)
	if len(prioritized) < 3 {
		t.Fatalf("expected 3 threats, got %d", len(prioritized))
	}

	// Critical should be first
	if prioritized[0].Severity != models.SeverityCritical {
		t.Errorf("expected first threat to be critical, got %s", prioritized[0].Severity)
	}

	// Low should be last
	if prioritized[len(prioritized)-1].Severity != models.SeverityLow {
		t.Errorf("expected last threat to be low, got %s", prioritized[len(prioritized)-1].Severity)
	}
}

func TestFilter_MinPriority(t *testing.T) {
	p := NewProcessor(ProcessorConfig{
		MinPriority: 7.0, // Only high/critical
		MaxAgeDays:  365,
	})

	threats := []*models.Threat{
		createTestThreat("low", "Low Priority", models.SeverityLow),
		createTestThreat("critical", "Critical Priority", models.SeverityCritical),
		createTestThreat("medium", "Medium Priority", models.SeverityMedium),
	}

	// Set priority scores
	for _, threat := range threats {
		threat.UpdatePriority()
	}

	filtered := p.filter(threats)

	// Only critical should pass
	for _, threat := range filtered {
		if threat.PriorityScore < 7.0 {
			t.Errorf("threat %s with priority %f should be filtered out", threat.ID, threat.PriorityScore)
		}
	}
}

func TestFilter_MaxAge(t *testing.T) {
	p := NewProcessor(ProcessorConfig{
		MinPriority: 0.0,
		MaxAgeDays:  7, // Only last 7 days
	})

	oldThreat := createTestThreat("old", "Old Threat", models.SeverityHigh)
	oldThreat.DiscoveredAt = time.Now().Add(-10 * 24 * time.Hour)

	newThreat := createTestThreat("new", "New Threat", models.SeverityHigh)
	newThreat.DiscoveredAt = time.Now()

	threats := []*models.Threat{oldThreat, newThreat}

	filtered := p.filter(threats)

	// Only new threat should pass
	if len(filtered) != 1 {
		t.Errorf("expected 1 filtered threat, got %d", len(filtered))
	}

	if len(filtered) > 0 && filtered[0].ID != "new" {
		t.Errorf("expected new threat to pass filter, got %s", filtered[0].ID)
	}
}

func TestFilter_FalsePositive(t *testing.T) {
	p := NewProcessor(ProcessorConfig{
		MinPriority: 0.0,
		MaxAgeDays:  365,
	})

	threat := createTestThreat("fp", "False Positive", models.SeverityHigh)
	threat.FalsePositive = true

	filtered := p.filter([]*models.Threat{threat})

	if len(filtered) != 0 {
		t.Error("false positive threat should be filtered out")
	}
}

func TestMergeThreats(t *testing.T) {
	p := NewProcessor(ProcessorConfig{})

	existing := createTestThreat("existing", "Existing Threat", models.SeverityMedium)
	existing.Indicators = []models.ThreatIndicator{
		{Value: "indicator1"},
	}
	existing.Tags = []string{"tag1"}
	existing.SourceFeeds = []string{"feed1"}

	new := createTestThreat("new", "New Data", models.SeverityHigh)
	new.Indicators = []models.ThreatIndicator{
		{Value: "indicator2"},
	}
	new.Tags = []string{"tag2"}
	new.SourceFeeds = []string{"feed2"}

	p.mergeThreats(existing, new)

	// Should merge indicators
	if len(existing.Indicators) != 2 {
		t.Errorf("expected 2 indicators after merge, got %d", len(existing.Indicators))
	}

	// Should merge tags
	if len(existing.Tags) != 2 {
		t.Errorf("expected 2 tags after merge, got %d", len(existing.Tags))
	}

	// Should merge source feeds
	if len(existing.SourceFeeds) != 2 {
		t.Errorf("expected 2 source feeds after merge, got %d", len(existing.SourceFeeds))
	}

	// Should take higher severity
	if existing.Severity != models.SeverityHigh {
		t.Errorf("expected severity to be updated to High, got %s", existing.Severity)
	}
}

func TestGetMetrics(t *testing.T) {
	p := NewProcessor(ProcessorConfig{})

	p.recordMetric("normalized", 10)
	p.recordMetric("enriched", 9)
	p.recordMetric("deduplicated", 8)

	metrics := p.GetMetrics()

	if metrics.Normalized != 10 {
		t.Errorf("expected Normalized=10, got %d", metrics.Normalized)
	}

	if metrics.Enriched != 9 {
		t.Errorf("expected Enriched=9, got %d", metrics.Enriched)
	}

	if metrics.Deduplicated != 8 {
		t.Errorf("expected Deduplicated=8, got %d", metrics.Deduplicated)
	}
}

func TestToLower(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"HELLO", "hello"},
		{"World", "world"},
		{"CVE-2024", "cve-2024"},
		{"already lowercase", "already lowercase"},
		{"MiXeD", "mixed"},
	}

	for _, tt := range tests {
		result := toLower(tt.input)
		if result != tt.expected {
			t.Errorf("toLower(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestSortByPriority(t *testing.T) {
	threats := []*models.Threat{
		{ID: "low", PriorityScore: 3.0},
		{ID: "high", PriorityScore: 9.0},
		{ID: "medium", PriorityScore: 6.0},
	}

	sortByPriority(threats)

	// Should be sorted descending
	if threats[0].PriorityScore != 9.0 {
		t.Errorf("expected first priority 9.0, got %f", threats[0].PriorityScore)
	}

	if threats[1].PriorityScore != 6.0 {
		t.Errorf("expected second priority 6.0, got %f", threats[1].PriorityScore)
	}

	if threats[2].PriorityScore != 3.0 {
		t.Errorf("expected third priority 3.0, got %f", threats[2].PriorityScore)
	}
}

// Helper function to create test threats
func createTestThreat(id, title string, severity models.ThreatSeverity) *models.Threat {
	return &models.Threat{
		ID:           id,
		Title:        title,
		Description:  "Test description for " + title,
		Severity:     severity,
		DiscoveredAt: time.Now(),
		UpdatedAt:    time.Now(),
		Tags:         []string{},
		Context:      models.ThreatContext{},
	}
}
