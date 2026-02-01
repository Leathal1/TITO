package models

import (
	"time"

	"github.com/Leathal1/TITO/pkg/stridelm"
)

// ThreatSeverity represents the severity level of a threat
type ThreatSeverity string

const (
	SeverityCritical ThreatSeverity = "critical"
	SeverityHigh     ThreatSeverity = "high"
	SeverityMedium   ThreatSeverity = "medium"
	SeverityLow      ThreatSeverity = "low"
	SeverityInfo     ThreatSeverity = "info"
)

// Score returns the numeric score for the severity (higher = more severe)
func (s ThreatSeverity) Score() int {
	switch s {
	case SeverityCritical:
		return 10
	case SeverityHigh:
		return 7
	case SeverityMedium:
		return 5
	case SeverityLow:
		return 3
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// IndicatorType represents the type of threat indicator
type IndicatorType string

const (
	IndicatorCVE             IndicatorType = "cve"
	IndicatorIPAddress       IndicatorType = "ip_address"
	IndicatorDomain          IndicatorType = "domain"
	IndicatorURL             IndicatorType = "url"
	IndicatorFileHash        IndicatorType = "file_hash"
	IndicatorEmail           IndicatorType = "email"
	IndicatorMalwareSignature IndicatorType = "malware_signature"
	IndicatorYaraRule        IndicatorType = "yara_rule"
	IndicatorAttackPattern   IndicatorType = "attack_pattern"
	IndicatorExploit         IndicatorType = "exploit"
	IndicatorTool            IndicatorType = "tool"
)

// ExploitationStatus represents the status of exploitation in the wild
type ExploitationStatus string

const (
	ExploitationActive      ExploitationStatus = "active"
	ExploitationPoCPublic   ExploitationStatus = "poc_public"
	ExploitationWeaponized  ExploitationStatus = "weaponized"
	ExploitationTheoretical ExploitationStatus = "theoretical"
	ExploitationUnknown     ExploitationStatus = "unknown"
)

// ThreatIndicator represents a single indicator of compromise or threat signal
// This is the atomic unit of threat intelligence.
type ThreatIndicator struct {
	ID          string                 `json:"id" yaml:"id"`
	Type        IndicatorType          `json:"type" yaml:"type"`
	Value       string                 `json:"value" yaml:"value"`
	Description string                 `json:"description" yaml:"description"`
	Confidence  float64                `json:"confidence" yaml:"confidence"` // 0.0 to 1.0
	FirstSeen   time.Time              `json:"first_seen" yaml:"first_seen"`
	LastSeen    time.Time              `json:"last_seen" yaml:"last_seen"`
	Tags        []string               `json:"tags" yaml:"tags"`
	Source      string                 `json:"source" yaml:"source"`
	RawData     map[string]interface{} `json:"raw_data,omitempty" yaml:"raw_data,omitempty"`
}

// ThreatContext represents contextual information that transforms data into intelligence
// This is what separates "here's a CVE" from "here's why this matters to YOU"
type ThreatContext struct {
	// Asset relevance
	AffectsKnownAssets  bool     `json:"affects_known_assets" yaml:"affects_known_assets"`
	AffectedAssetTypes  []string `json:"affected_asset_types" yaml:"affected_asset_types"`
	AffectedTechnologies []string `json:"affected_technologies" yaml:"affected_technologies"`

	// Attack surface
	ExposureLevel             string `json:"exposure_level" yaml:"exposure_level"`                             // internet, internal, isolated
	AttackComplexity          string `json:"attack_complexity" yaml:"attack_complexity"`                       // low, medium, high
	UserInteractionRequired   bool   `json:"user_interaction_required" yaml:"user_interaction_required"`
	PrivilegesRequired        string `json:"privileges_required" yaml:"privileges_required"`                   // none, low, high

	// Intelligence enrichment
	ExploitationStatus      ExploitationStatus `json:"exploitation_status" yaml:"exploitation_status"`
	ExploitMaturity         string             `json:"exploit_maturity" yaml:"exploit_maturity"` // unproven, poc, functional, high
	KnownCampaigns          []string           `json:"known_campaigns" yaml:"known_campaigns"`
	ThreatActorAttribution  []string           `json:"threat_actor_attribution" yaml:"threat_actor_attribution"`

	// Historical
	SimilarIncidentsCount int      `json:"similar_incidents_count" yaml:"similar_incidents_count"`
	HistoricalImpact      []string `json:"historical_impact" yaml:"historical_impact"`

	// Mitigation
	MitigationAvailable  bool   `json:"mitigation_available" yaml:"mitigation_available"`
	PatchAvailable       bool   `json:"patch_available" yaml:"patch_available"`
	WorkaroundAvailable  bool   `json:"workaround_available" yaml:"workaround_available"`
	MitigationComplexity string `json:"mitigation_complexity" yaml:"mitigation_complexity"` // low, medium, high
}

// CalculateUrgencyScore calculates urgency score (0.0 to 1.0)
// The answer to: "How fast should we respond?"
func (tc *ThreatContext) CalculateUrgencyScore() float64 {
	score := 0.0

	// Exploitation status is critical
	switch tc.ExploitationStatus {
	case ExploitationActive:
		score += 0.4
	case ExploitationWeaponized:
		score += 0.3
	case ExploitationPoCPublic:
		score += 0.2
	case ExploitationTheoretical:
		score += 0.05
	default:
		score += 0.1
	}

	// Asset relevance
	if tc.AffectsKnownAssets {
		score += 0.25
	}

	// Exposure
	switch tc.ExposureLevel {
	case "internet":
		score += 0.2
	case "internal":
		score += 0.1
	case "isolated":
		score += 0.05
	default:
		score += 0.1
	}

	// Attack complexity (lower is worse)
	switch tc.AttackComplexity {
	case "low":
		score += 0.15
	case "medium":
		score += 0.08
	case "high":
		score += 0.03
	default:
		score += 0.05
	}

	if score > 1.0 {
		return 1.0
	}
	return score
}

// Threat represents a threat intelligence entry
// This is intelligence, not data. Every threat that reaches a human
// should deserve to reach a human.
type Threat struct {
	ID          string                `json:"id" yaml:"id"`
	Title       string                `json:"title" yaml:"title"`
	Description string                `json:"description" yaml:"description"`
	Severity    ThreatSeverity        `json:"severity" yaml:"severity"`

	// STRIDE-LM classification
	StrideProfile *stridelm.Profile `json:"stride_profile,omitempty" yaml:"stride_profile,omitempty"`

	// Indicators
	Indicators []ThreatIndicator `json:"indicators" yaml:"indicators"`

	// Context (this is what makes it intelligence)
	Context ThreatContext `json:"context" yaml:"context"`

	// Temporal
	DiscoveredAt time.Time  `json:"discovered_at" yaml:"discovered_at"`
	PublishedAt  *time.Time `json:"published_at,omitempty" yaml:"published_at,omitempty"`
	UpdatedAt    time.Time  `json:"updated_at" yaml:"updated_at"`

	// References
	References      []string `json:"references" yaml:"references"`
	CVEIDs          []string `json:"cve_ids" yaml:"cve_ids"`
	MitreAttackIDs  []string `json:"mitre_attack_ids" yaml:"mitre_attack_ids"`
	PCIRequirements []string `json:"pci_requirements,omitempty" yaml:"pci_requirements,omitempty"`

	// Recommendations
	RecommendedActions []string `json:"recommended_actions" yaml:"recommended_actions"`
	DetectionRules     []string `json:"detection_rules" yaml:"detection_rules"`

	// Metadata
	Tags          []string `json:"tags" yaml:"tags"`
	PriorityScore float64  `json:"priority_score" yaml:"priority_score"` // 0.0 to 1.0

	// Tracking
	SourceFeeds   []string `json:"source_feeds" yaml:"source_feeds"`
	AnalystNotes  string   `json:"analyst_notes,omitempty" yaml:"analyst_notes,omitempty"`
	FalsePositive bool     `json:"false_positive" yaml:"false_positive"`
	InstanceCount int      `json:"instance_count" yaml:"instance_count"` // Number of consolidated instances
}

// CalculatePriorityScore calculates priority score (0.0 to 1.0)
// The answer to: "Should I care about this threat RIGHT NOW?"
//
// Combines severity, context, and urgency into a single score
// that helps analysts focus on what matters.
func (t *Threat) CalculatePriorityScore() float64 {
	// Base score from severity
	severityWeight := 0.3
	severityScore := float64(t.Severity.Score()) / 10.0

	// Urgency from context
	urgencyWeight := 0.4
	urgencyScore := t.Context.CalculateUrgencyScore()

	// STRIDE-LM categories add nuance
	strideWeight := 0.2
	strideScore := 0.5 // Default
	if t.StrideProfile != nil {
		// Higher confidence = higher score
		var totalConfidence float64
		confidenceCount := 0
		for _, score := range t.StrideProfile.ConfidenceScores {
			totalConfidence += score
			confidenceCount++
		}
		if confidenceCount > 0 {
			strideScore = totalConfidence / float64(confidenceCount)
		}
	}

	// Recency matters
	recencyWeight := 0.1
	ageDays := time.Since(t.DiscoveredAt).Hours() / 24
	recencyScore := 1.0 - (ageDays / 30.0) // Decay over 30 days
	if recencyScore < 0 {
		recencyScore = 0
	}

	totalScore := severityWeight*severityScore +
		urgencyWeight*urgencyScore +
		strideWeight*strideScore +
		recencyWeight*recencyScore

	if totalScore > 1.0 {
		return 1.0
	}
	return totalScore
}

// UpdatePriority recalculates and updates priority score
func (t *Threat) UpdatePriority() {
	t.PriorityScore = t.CalculatePriorityScore()
	t.UpdatedAt = time.Now()
}

// AddIndicator adds an indicator and updates timestamp
func (t *Threat) AddIndicator(indicator ThreatIndicator) {
	t.Indicators = append(t.Indicators, indicator)
	t.UpdatedAt = time.Now()
}
