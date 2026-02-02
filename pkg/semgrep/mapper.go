package semgrep

import (
	"strings"

	"github.com/Leathal1/TITO/v2/pkg/maestro"
	"github.com/Leathal1/TITO/v2/pkg/stridelm"
)

// ThreatMapping represents a mapping from Semgrep findings to threat frameworks
type ThreatMapping struct {
	Finding        Finding
	STRIDECategory stridelm.Category
	MAESTROLayer   maestro.Layer
	Confidence     float64
	Reason         string
}

// Mapper maps Semgrep findings to STRIDE-LM and MAESTRO frameworks
type Mapper struct {
	strideClassifier  *stridelm.Classifier
	maestroClassifier *maestro.Classifier
}

// NewMapper creates a new Semgrep to threat framework mapper
func NewMapper() *Mapper {
	return &Mapper{
		strideClassifier:  stridelm.NewClassifier(),
		maestroClassifier: maestro.NewClassifier(),
	}
}

// MapFinding maps a single Semgrep finding to threat frameworks
func (m *Mapper) MapFinding(finding Finding) ThreatMapping {
	mapping := ThreatMapping{
		Finding:    finding,
		Confidence: m.calculateConfidence(finding),
	}

	// Extract CWE IDs
	cweIDs := GetCWEIDs(finding)

	// Build description from finding metadata
	description := finding.Extra.Message
	if finding.Extra.Metadata.Category != "" {
		description += " " + finding.Extra.Metadata.Category
	}
	for _, vulnClass := range finding.Extra.Metadata.VulnerabilityClass {
		description += " " + vulnClass
	}

	// Map to STRIDE-LM
	strideInput := stridelm.ClassificationInput{
		Text:   description,
		CWEIDs: cweIDs,
	}
	strideProfile := m.strideClassifier.Classify(strideInput)
	mapping.STRIDECategory = strideProfile.PrimaryCategory

	// Map to MAESTRO if applicable
	maestroLayer := m.inferMAESTROLayer(finding, description)
	mapping.MAESTROLayer = maestroLayer

	mapping.Reason = m.buildReason(finding, strideProfile.PrimaryCategory, maestroLayer)

	return mapping
}

// MapFindings maps multiple Semgrep findings
func (m *Mapper) MapFindings(findings []Finding) []ThreatMapping {
	mappings := make([]ThreatMapping, 0, len(findings))
	for _, finding := range findings {
		mapping := m.MapFinding(finding)
		mappings = append(mappings, mapping)
	}
	return mappings
}

// inferMAESTROLayer infers MAESTRO layer from Semgrep finding context
func (m *Mapper) inferMAESTROLayer(finding Finding, description string) maestro.Layer {
	descLower := strings.ToLower(description)
	checkID := strings.ToLower(finding.CheckID)
	combined := descLower + " " + checkID

	// Check for AI/ML specific patterns
	aiKeywords := []string{"llm", "gpt", "ai", "model", "prompt", "agent", "rag", "embedding"}
	hasAIContext := false
	for _, keyword := range aiKeywords {
		if strings.Contains(combined, keyword) {
			hasAIContext = true
			break
		}
	}

	if !hasAIContext {
		// Not AI-specific, return empty
		return ""
	}

	// Foundation Models Layer
	if strings.Contains(combined, "prompt injection") ||
		strings.Contains(combined, "jailbreak") ||
		strings.Contains(combined, "model") ||
		strings.Contains(combined, "llm") {
		return maestro.FoundationModels
	}

	// Data & Knowledge Layer
	if strings.Contains(combined, "rag") ||
		strings.Contains(combined, "vector") ||
		strings.Contains(combined, "embedding") ||
		strings.Contains(combined, "knowledge") {
		return maestro.DataKnowledge
	}

	// Agent Frameworks Layer
	if strings.Contains(combined, "agent") ||
		strings.Contains(combined, "langchain") ||
		strings.Contains(combined, "autogen") ||
		strings.Contains(combined, "tool calling") {
		return maestro.AgentFrameworks
	}

	// Tooling & Integration Layer
	if strings.Contains(combined, "api key") ||
		strings.Contains(combined, "credential") ||
		strings.Contains(combined, "token") ||
		strings.Contains(combined, "secret") {
		return maestro.ToolingIntegration
	}

	// Deployment & Infrastructure Layer
	if strings.Contains(combined, "container") ||
		strings.Contains(combined, "docker") ||
		strings.Contains(combined, "kubernetes") ||
		strings.Contains(combined, "resource") {
		return maestro.DeploymentInfra
	}

	// Default to Foundation Models for AI context
	return maestro.FoundationModels
}

// calculateConfidence calculates confidence score for the mapping
func (m *Mapper) calculateConfidence(finding Finding) float64 {
	baseConfidence := 0.5

	// Severity contributes to confidence
	switch SeverityLevel(strings.ToUpper(finding.Extra.Severity)) {
	case SeverityError:
		baseConfidence += 0.3
	case SeverityWarning:
		baseConfidence += 0.2
	case SeverityInfo:
		baseConfidence += 0.1
	}

	// Metadata confidence
	switch ConfidenceLevel(strings.ToUpper(finding.Extra.Metadata.Confidence)) {
	case ConfidenceHigh:
		baseConfidence += 0.2
	case ConfidenceMedium:
		baseConfidence += 0.1
	case ConfidenceLow:
		baseConfidence += 0.05
	}

	// CWE presence increases confidence
	if len(finding.Extra.Metadata.CWE) > 0 {
		baseConfidence += 0.1
	}

	if baseConfidence > 1.0 {
		return 1.0
	}
	return baseConfidence
}

// buildReason builds an explanation for the mapping
func (m *Mapper) buildReason(finding Finding, strideCategory stridelm.Category, maestroLayer maestro.Layer) string {
	var parts []string

	parts = append(parts, finding.Extra.Message)

	if finding.Extra.Metadata.Category != "" {
		parts = append(parts, "Category: "+finding.Extra.Metadata.Category)
	}

	if len(finding.Extra.Metadata.CWE) > 0 {
		parts = append(parts, "CWE: "+strings.Join(finding.Extra.Metadata.CWE, ", "))
	}

	strideInfo := stridelm.GetCategoryInfo(strideCategory)
	if strideInfo.FullName != "" {
		parts = append(parts, "STRIDE-LM: "+strideInfo.FullName)
	}

	if maestroLayer != "" {
		maestroInfo := maestro.GetLayerInfo(maestroLayer)
		if maestroInfo.FullName != "" {
			parts = append(parts, "MAESTRO: "+maestroInfo.FullName)
		}
	}

	return strings.Join(parts, " | ")
}

// GroupBySTRIDE groups mappings by STRIDE-LM category
func GroupBySTRIDE(mappings []ThreatMapping) map[stridelm.Category][]ThreatMapping {
	groups := make(map[stridelm.Category][]ThreatMapping)

	for _, mapping := range mappings {
		category := mapping.STRIDECategory
		groups[category] = append(groups[category], mapping)
	}

	return groups
}

// GroupByMAESTRO groups mappings by MAESTRO layer
func GroupByMAESTRO(mappings []ThreatMapping) map[maestro.Layer][]ThreatMapping {
	groups := make(map[maestro.Layer][]ThreatMapping)

	for _, mapping := range mappings {
		layer := mapping.MAESTROLayer
		if layer != "" { // Only include if MAESTRO layer is applicable
			groups[layer] = append(groups[layer], mapping)
		}
	}

	return groups
}

// GetHighConfidenceMappings filters mappings by minimum confidence
func GetHighConfidenceMappings(mappings []ThreatMapping, minConfidence float64) []ThreatMapping {
	var filtered []ThreatMapping
	for _, mapping := range mappings {
		if mapping.Confidence >= minConfidence {
			filtered = append(filtered, mapping)
		}
	}
	return filtered
}
