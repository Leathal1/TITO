package models

import (
	"testing"
	"time"

	"github.com/Leathal1/TITO/pkg/stridelm"
)

func TestThreatSeverity_Score(t *testing.T) {
	tests := []struct {
		severity ThreatSeverity
		expected int
	}{
		{SeverityCritical, 10},
		{SeverityHigh, 7},
		{SeverityMedium, 5},
		{SeverityLow, 3},
		{SeverityInfo, 1},
		{ThreatSeverity("unknown"), 0},
	}

	for _, tt := range tests {
		score := tt.severity.Score()
		if score != tt.expected {
			t.Errorf("%s.Score() = %d, want %d", tt.severity, score, tt.expected)
		}
	}
}

func TestThreatContext_CalculateUrgencyScore(t *testing.T) {
	// Test active exploitation + known assets + internet exposure
	ctx := ThreatContext{
		ExploitationStatus: ExploitationActive,
		AffectsKnownAssets: true,
		ExposureLevel:      "internet",
		AttackComplexity:   "low",
	}

	score := ctx.CalculateUrgencyScore()

	// This should be a high urgency score
	if score < 0.8 {
		t.Errorf("expected high urgency score for active exploitation, got %f", score)
	}

	if score > 1.0 {
		t.Errorf("urgency score should not exceed 1.0, got %f", score)
	}
}

func TestThreatContext_CalculateUrgencyScore_Low(t *testing.T) {
	// Test theoretical + no known assets + isolated
	ctx := ThreatContext{
		ExploitationStatus: ExploitationTheoretical,
		AffectsKnownAssets: false,
		ExposureLevel:      "isolated",
		AttackComplexity:   "high",
	}

	score := ctx.CalculateUrgencyScore()

	// This should be a low urgency score
	if score > 0.3 {
		t.Errorf("expected low urgency score for theoretical threat, got %f", score)
	}

	if score < 0.0 {
		t.Errorf("urgency score should not be negative, got %f", score)
	}
}

func TestThreatContext_CalculateUrgencyScore_AllStatuses(t *testing.T) {
	statuses := []ExploitationStatus{
		ExploitationActive,
		ExploitationWeaponized,
		ExploitationPoCPublic,
		ExploitationTheoretical,
		ExploitationUnknown,
	}

	for _, status := range statuses {
		ctx := ThreatContext{
			ExploitationStatus: status,
		}
		score := ctx.CalculateUrgencyScore()

		if score < 0.0 || score > 1.0 {
			t.Errorf("urgency score for status %s out of range: %f", status, score)
		}
	}
}

func TestThreat_CalculatePriorityScore(t *testing.T) {
	threat := &Threat{
		Severity:     SeverityCritical,
		DiscoveredAt: time.Now(),
		Context: ThreatContext{
			ExploitationStatus: ExploitationActive,
			AffectsKnownAssets: true,
			ExposureLevel:      "internet",
			AttackComplexity:   "low",
		},
		StrideProfile: &stridelm.Profile{
			PrimaryCategory: stridelm.Spoofing,
			ConfidenceScores: map[stridelm.Category]float64{
				stridelm.Spoofing: 0.9,
			},
		},
	}

	score := threat.CalculatePriorityScore()

	// High severity + active exploitation should = high priority
	if score < 0.7 {
		t.Errorf("expected high priority score for critical active threat, got %f", score)
	}

	if score > 1.0 {
		t.Errorf("priority score should not exceed 1.0, got %f", score)
	}
}

func TestThreat_CalculatePriorityScore_Recency(t *testing.T) {
	// Fresh threat
	freshThreat := &Threat{
		Severity:     SeverityHigh,
		DiscoveredAt: time.Now(),
		Context:      ThreatContext{},
	}

	// Old threat (60 days ago)
	oldThreat := &Threat{
		Severity:     SeverityHigh,
		DiscoveredAt: time.Now().Add(-60 * 24 * time.Hour),
		Context:      ThreatContext{},
	}

	freshScore := freshThreat.CalculatePriorityScore()
	oldScore := oldThreat.CalculatePriorityScore()

	// Fresh threat should have higher priority
	if freshScore <= oldScore {
		t.Errorf("fresh threat (%f) should have higher priority than old threat (%f)", freshScore, oldScore)
	}
}

func TestThreat_UpdatePriority(t *testing.T) {
	threat := &Threat{
		Severity:     SeverityMedium,
		DiscoveredAt: time.Now(),
		UpdatedAt:    time.Now().Add(-1 * time.Hour),
		Context:      ThreatContext{},
	}

	oldUpdatedAt := threat.UpdatedAt
	oldScore := threat.PriorityScore

	// Sleep briefly to ensure time difference
	time.Sleep(10 * time.Millisecond)

	threat.UpdatePriority()

	// UpdatedAt should be newer
	if !threat.UpdatedAt.After(oldUpdatedAt) {
		t.Error("UpdatedAt should be updated")
	}

	// PriorityScore should be calculated
	if threat.PriorityScore == oldScore && oldScore == 0 {
		t.Error("PriorityScore should be calculated")
	}
}

func TestThreat_AddIndicator(t *testing.T) {
	threat := &Threat{
		Indicators: []ThreatIndicator{},
		UpdatedAt:  time.Now().Add(-1 * time.Hour),
	}

	oldUpdatedAt := threat.UpdatedAt
	oldCount := len(threat.Indicators)

	// Sleep briefly to ensure time difference
	time.Sleep(10 * time.Millisecond)

	indicator := ThreatIndicator{
		ID:    "ind-1",
		Type:  IndicatorCVE,
		Value: "CVE-2024-1234",
	}

	threat.AddIndicator(indicator)

	// Should add indicator
	if len(threat.Indicators) != oldCount+1 {
		t.Errorf("expected %d indicators, got %d", oldCount+1, len(threat.Indicators))
	}

	// Should update timestamp
	if !threat.UpdatedAt.After(oldUpdatedAt) {
		t.Error("UpdatedAt should be updated when adding indicator")
	}

	// Verify indicator was added correctly
	if threat.Indicators[0].ID != "ind-1" {
		t.Errorf("expected indicator ID 'ind-1', got %s", threat.Indicators[0].ID)
	}
}

func TestThreatIndicator_Types(t *testing.T) {
	types := []IndicatorType{
		IndicatorCVE,
		IndicatorIPAddress,
		IndicatorDomain,
		IndicatorURL,
		IndicatorFileHash,
		IndicatorEmail,
		IndicatorMalwareSignature,
		IndicatorYaraRule,
		IndicatorAttackPattern,
		IndicatorExploit,
		IndicatorTool,
	}

	for _, indicatorType := range types {
		indicator := ThreatIndicator{
			Type: indicatorType,
		}

		if indicator.Type != indicatorType {
			t.Errorf("expected type %s, got %s", indicatorType, indicator.Type)
		}
	}
}

func TestThreat_PriorityScore_WithoutStrideProfile(t *testing.T) {
	threat := &Threat{
		Severity:     SeverityHigh,
		DiscoveredAt: time.Now(),
		Context: ThreatContext{
			ExploitationStatus: ExploitationPoCPublic,
		},
		StrideProfile: nil, // No STRIDE profile
	}

	score := threat.CalculatePriorityScore()

	// Should still calculate score without STRIDE profile
	if score <= 0.0 {
		t.Error("priority score should be > 0 even without STRIDE profile")
	}

	if score > 1.0 {
		t.Errorf("priority score should not exceed 1.0, got %f", score)
	}
}

func TestThreat_PriorityScore_MultipleStrideCategories(t *testing.T) {
	threat := &Threat{
		Severity:     SeverityHigh,
		DiscoveredAt: time.Now(),
		Context:      ThreatContext{},
		StrideProfile: &stridelm.Profile{
			PrimaryCategory: stridelm.Tampering,
			ConfidenceScores: map[stridelm.Category]float64{
				stridelm.Tampering:     0.9,
				stridelm.InfoDisclosure: 0.7,
				stridelm.Elevation:     0.5,
			},
		},
	}

	score := threat.CalculatePriorityScore()

	// Multiple high-confidence categories should contribute to score
	if score <= 0.0 {
		t.Error("priority score should be > 0 with multiple STRIDE categories")
	}
}

func TestExploitationStatus_AllValues(t *testing.T) {
	statuses := []ExploitationStatus{
		ExploitationActive,
		ExploitationPoCPublic,
		ExploitationWeaponized,
		ExploitationTheoretical,
		ExploitationUnknown,
	}

	for _, status := range statuses {
		ctx := ThreatContext{
			ExploitationStatus: status,
		}

		// Just verify it doesn't panic
		_ = ctx.CalculateUrgencyScore()
	}
}

func TestThreatContext_ExposureLevels(t *testing.T) {
	levels := []string{"internet", "internal", "isolated", "unknown"}

	for _, level := range levels {
		ctx := ThreatContext{
			ExposureLevel: level,
		}

		score := ctx.CalculateUrgencyScore()

		// All should produce valid scores
		if score < 0.0 || score > 1.0 {
			t.Errorf("urgency score for exposure level %s out of range: %f", level, score)
		}
	}
}

func TestThreatContext_AttackComplexity(t *testing.T) {
	complexities := []string{"low", "medium", "high", "unknown"}

	for _, complexity := range complexities {
		ctx := ThreatContext{
			AttackComplexity: complexity,
		}

		score := ctx.CalculateUrgencyScore()

		// All should produce valid scores
		if score < 0.0 || score > 1.0 {
			t.Errorf("urgency score for attack complexity %s out of range: %f", complexity, score)
		}
	}
}

func TestThreat_FullLifecycle(t *testing.T) {
	// Create a new threat
	threat := &Threat{
		ID:           "threat-test-1",
		Title:        "Test Threat",
		Description:  "This is a test threat",
		Severity:     SeverityCritical,
		DiscoveredAt: time.Now(),
		UpdatedAt:    time.Now(),
		Context: ThreatContext{
			ExploitationStatus: ExploitationActive,
			AffectsKnownAssets: true,
			ExposureLevel:      "internet",
			AttackComplexity:   "low",
		},
		Tags:        []string{"test", "critical"},
		CVEIDs:      []string{"CVE-2024-TEST"},
		SourceFeeds: []string{"test-feed"},
	}

	// Calculate initial priority
	threat.UpdatePriority()
	initialPriority := threat.PriorityScore

	if initialPriority <= 0 {
		t.Error("initial priority should be > 0")
	}

	// Add an indicator
	threat.AddIndicator(ThreatIndicator{
		ID:         "ind-1",
		Type:       IndicatorCVE,
		Value:      "CVE-2024-TEST",
		Confidence: 1.0,
		FirstSeen:  time.Now(),
		LastSeen:   time.Now(),
	})

	if len(threat.Indicators) != 1 {
		t.Errorf("expected 1 indicator, got %d", len(threat.Indicators))
	}

	// Update context (e.g., patch becomes available)
	threat.Context.PatchAvailable = true
	threat.Context.MitigationAvailable = true

	// Mark as false positive
	threat.FalsePositive = false

	// Verify final state
	if threat.ID != "threat-test-1" {
		t.Errorf("threat ID changed unexpectedly: %s", threat.ID)
	}

	if threat.Severity != SeverityCritical {
		t.Error("severity changed unexpectedly")
	}
}

func TestIndicatorType_Constants(t *testing.T) {
	// Just verify all constants are defined
	types := []IndicatorType{
		IndicatorCVE,
		IndicatorIPAddress,
		IndicatorDomain,
		IndicatorURL,
		IndicatorFileHash,
		IndicatorEmail,
		IndicatorMalwareSignature,
		IndicatorYaraRule,
		IndicatorAttackPattern,
		IndicatorExploit,
		IndicatorTool,
	}

	if len(types) != 11 {
		t.Errorf("expected 11 indicator types, got %d", len(types))
	}
}

func TestSeverity_Constants(t *testing.T) {
	severities := []ThreatSeverity{
		SeverityCritical,
		SeverityHigh,
		SeverityMedium,
		SeverityLow,
		SeverityInfo,
	}

	if len(severities) != 5 {
		t.Errorf("expected 5 severity levels, got %d", len(severities))
	}

	// Verify scores are ordered correctly
	for i := 0; i < len(severities)-1; i++ {
		if severities[i].Score() <= severities[i+1].Score() {
			t.Errorf("severity %s (score %d) should have higher score than %s (score %d)",
				severities[i], severities[i].Score(),
				severities[i+1], severities[i+1].Score())
		}
	}
}
