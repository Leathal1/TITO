package maestro

import (
	"regexp"
	"strings"
)

// Profile represents a MAESTRO classification profile
type Profile struct {
	PrimaryLayer       Layer              `json:"primary_layer" yaml:"primary_layer"`
	SecondaryLayers    []Layer            `json:"secondary_layers" yaml:"secondary_layers"`
	ConfidenceScores   map[Layer]float64  `json:"confidence_scores" yaml:"confidence_scores"`
	IdentifiedThreats  []string           `json:"identified_threats" yaml:"identified_threats"`
}

// String returns a human-readable representation
func (p *Profile) String() string {
	result := string(p.PrimaryLayer)
	if len(p.SecondaryLayers) > 0 {
		var secondary []string
		for _, layer := range p.SecondaryLayers {
			secondary = append(secondary, string(layer))
		}
		result += "(" + strings.Join(secondary, ",") + ")"
	}
	return result
}

// Classifier performs MAESTRO classification for agentic AI threats
type Classifier struct {
	layers   map[Layer]LayerInfo
	patterns map[Layer][]*regexp.Regexp
}

// NewClassifier creates a new MAESTRO classifier
func NewClassifier() *Classifier {
	c := &Classifier{
		layers:   AllLayers(),
		patterns: make(map[Layer][]*regexp.Regexp),
	}

	// Compile regex patterns for each layer
	for layer, info := range c.layers {
		var patterns []*regexp.Regexp
		for _, keyword := range info.Keywords {
			// Match whole words, case insensitive
			pattern := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(keyword) + `\b`)
			patterns = append(patterns, pattern)
		}
		c.patterns[layer] = patterns
	}

	return c
}

// ClassificationInput holds input data for MAESTRO classification
type ClassificationInput struct {
	SystemDescription string
	Technologies      []string
	DeploymentModel   string // cloud, on-prem, hybrid, edge
	HasAgents         bool
	HasRAG            bool
	HasToolCalling    bool
	HasMultiAgent     bool
	CWEIDs            []int
	Context           map[string]interface{}
}

// Classify classifies a system into MAESTRO layers
func (c *Classifier) Classify(input ClassificationInput) *Profile {
	// Calculate confidence scores for each layer
	scores := c.calculateScores(input)

	// Sort layers by score to determine primary and secondary
	var sortedLayers []Layer
	for layer := range scores {
		sortedLayers = append(sortedLayers, layer)
	}

	// Simple bubble sort by score (descending)
	for i := 0; i < len(sortedLayers); i++ {
		for j := i + 1; j < len(sortedLayers); j++ {
			if scores[sortedLayers[i]] < scores[sortedLayers[j]] {
				sortedLayers[i], sortedLayers[j] = sortedLayers[j], sortedLayers[i]
			}
		}
	}

	// Primary layer is the highest scoring
	primaryLayer := sortedLayers[0]

	// Secondary layers are those with score > threshold
	secondaryThreshold := 0.3
	var secondaryLayers []Layer
	for i := 1; i < len(sortedLayers); i++ {
		layer := sortedLayers[i]
		if scores[layer] >= secondaryThreshold {
			secondaryLayers = append(secondaryLayers, layer)
		}
	}

	// Identify specific threats based on classification
	threats := c.identifyThreats(input, primaryLayer, secondaryLayers)

	return &Profile{
		PrimaryLayer:      primaryLayer,
		SecondaryLayers:   secondaryLayers,
		ConfidenceScores:  scores,
		IdentifiedThreats: threats,
	}
}

// calculateScores calculates confidence scores for each MAESTRO layer
func (c *Classifier) calculateScores(input ClassificationInput) map[Layer]float64 {
	scores := make(map[Layer]float64)

	// Initialize all layers with 0.0
	for layer := range c.layers {
		scores[layer] = 0.0
	}

	// Signal 1: Keyword matching in description (weight: 0.3)
	keywordScores := c.scoreKeywords(input.SystemDescription)
	for layer, score := range keywordScores {
		scores[layer] += 0.3 * score
	}

	// Signal 2: Technology stack analysis (weight: 0.25)
	techScores := c.scoreTechnologies(input.Technologies)
	for layer, score := range techScores {
		scores[layer] += 0.25 * score
	}

	// Signal 3: System architecture (weight: 0.25)
	archScores := c.scoreArchitecture(input)
	for layer, score := range archScores {
		scores[layer] += 0.25 * score
	}

	// Signal 4: CWE ID mapping (weight: 0.15)
	if len(input.CWEIDs) > 0 {
		cweScores := c.scoreCWEIDs(input.CWEIDs)
		for layer, score := range cweScores {
			scores[layer] += 0.15 * score
		}
	}

	// Signal 5: Contextual heuristics (weight: 0.05)
	if input.Context != nil {
		contextScores := c.scoreContext(input.Context)
		for layer, score := range contextScores {
			scores[layer] += 0.05 * score
		}
	}

	// Normalize scores to 0-1 range
	maxScore := 0.0
	for _, score := range scores {
		if score > maxScore {
			maxScore = score
		}
	}

	if maxScore > 0 {
		for layer := range scores {
			scores[layer] = scores[layer] / maxScore
		}
	}

	// Ensure at least one layer has a minimum score
	allLow := true
	for _, score := range scores {
		if score >= 0.1 {
			allLow = false
			break
		}
	}
	if allLow {
		// Default to Foundation Models layer for AI threats
		scores[FoundationModels] = 0.5
	}

	return scores
}

// scoreKeywords scores layers based on keyword matches
func (c *Classifier) scoreKeywords(text string) map[Layer]float64 {
	scores := make(map[Layer]float64)

	for layer, patterns := range c.patterns {
		matches := 0
		for _, pattern := range patterns {
			if pattern.MatchString(text) {
				matches++
			}
		}

		// Score is proportional to number of keyword matches
		if matches > 0 {
			score := float64(matches) / 3.0 // Cap at 3 matches
			if score > 1.0 {
				score = 1.0
			}
			scores[layer] = score
		} else {
			scores[layer] = 0.0
		}
	}

	return scores
}

// scoreTechnologies scores layers based on technology stack
func (c *Classifier) scoreTechnologies(technologies []string) map[Layer]float64 {
	scores := make(map[Layer]float64)

	// Initialize all scores to 0
	for layer := range c.layers {
		scores[layer] = 0.0
	}

	techLower := make([]string, len(technologies))
	for i, tech := range technologies {
		techLower[i] = strings.ToLower(tech)
	}

	for _, tech := range techLower {
		// Foundation Models Layer
		if strings.Contains(tech, "gpt") || strings.Contains(tech, "claude") ||
			strings.Contains(tech, "llama") || strings.Contains(tech, "gemini") ||
			strings.Contains(tech, "anthropic") || strings.Contains(tech, "openai") {
			scores[FoundationModels] += 0.5
		}

		// Data & Knowledge Layer
		if strings.Contains(tech, "rag") || strings.Contains(tech, "vector") ||
			strings.Contains(tech, "chroma") || strings.Contains(tech, "pinecone") ||
			strings.Contains(tech, "weaviate") || strings.Contains(tech, "embedding") {
			scores[DataKnowledge] += 0.5
		}

		// Agent Frameworks Layer
		if strings.Contains(tech, "langchain") || strings.Contains(tech, "autogen") ||
			strings.Contains(tech, "crewai") || strings.Contains(tech, "haystack") ||
			strings.Contains(tech, "semantic kernel") {
			scores[AgentFrameworks] += 0.5
		}

		// Tooling & Integration Layer
		if strings.Contains(tech, "mcp") || strings.Contains(tech, "plugin") ||
			strings.Contains(tech, "api") || strings.Contains(tech, "integration") {
			scores[ToolingIntegration] += 0.3
		}

		// Deployment & Infrastructure Layer
		if strings.Contains(tech, "docker") || strings.Contains(tech, "kubernetes") ||
			strings.Contains(tech, "aws") || strings.Contains(tech, "azure") ||
			strings.Contains(tech, "gcp") || strings.Contains(tech, "cloud") {
			scores[DeploymentInfra] += 0.3
		}
	}

	// Normalize to 0-1
	for layer := range scores {
		if scores[layer] > 1.0 {
			scores[layer] = 1.0
		}
	}

	return scores
}

// scoreArchitecture scores layers based on system architecture
func (c *Classifier) scoreArchitecture(input ClassificationInput) map[Layer]float64 {
	scores := make(map[Layer]float64)

	// Initialize all scores to 0
	for layer := range c.layers {
		scores[layer] = 0.0
	}

	// Agent-based systems
	if input.HasAgents {
		scores[FoundationModels] += 0.4
		scores[AgentFrameworks] += 0.6
	}

	// RAG systems
	if input.HasRAG {
		scores[DataKnowledge] += 0.8
		scores[FoundationModels] += 0.3
	}

	// Tool calling
	if input.HasToolCalling {
		scores[ToolingIntegration] += 0.7
		scores[AgentFrameworks] += 0.4
	}

	// Multi-agent systems
	if input.HasMultiAgent {
		scores[AgentCommunication] += 0.9
		scores[AgentFrameworks] += 0.5
	}

	// Deployment model
	switch strings.ToLower(input.DeploymentModel) {
	case "cloud", "saas":
		scores[DeploymentInfra] += 0.6
		scores[EcosystemGovernance] += 0.3
	case "on-prem", "self-hosted":
		scores[DeploymentInfra] += 0.5
	case "hybrid":
		scores[DeploymentInfra] += 0.7
		scores[AgentCommunication] += 0.3
	}

	// Normalize to 0-1
	for layer := range scores {
		if scores[layer] > 1.0 {
			scores[layer] = 1.0
		}
	}

	return scores
}

// scoreCWEIDs scores layers based on CWE ID mappings
func (c *Classifier) scoreCWEIDs(cweIDs []int) map[Layer]float64 {
	scores := make(map[Layer]float64)

	// Initialize all scores to 0
	for layer := range c.layers {
		scores[layer] = 0.0
	}

	// Check each CWE ID against layer mappings
	for layer, info := range c.layers {
		for _, inputCWE := range cweIDs {
			for _, layerCWE := range info.CWEIDs {
				if inputCWE == layerCWE {
					// Strong signal - CWE IDs are authoritative
					scores[layer] = 1.0
					break
				}
			}
		}
	}

	return scores
}

// scoreContext scores layers based on contextual information
func (c *Classifier) scoreContext(context map[string]interface{}) map[Layer]float64 {
	scores := make(map[Layer]float64)

	// Initialize all scores to 0
	for layer := range c.layers {
		scores[layer] = 0.0
	}

	// Model-related context
	if usesLLM, ok := context["uses_llm"].(bool); ok && usesLLM {
		scores[FoundationModels] += 0.6
	}

	// Data pipeline context
	if hasDataPipeline, ok := context["has_data_pipeline"].(bool); ok && hasDataPipeline {
		scores[DataKnowledge] += 0.5
	}

	// External integrations
	if hasIntegrations, ok := context["has_external_integrations"].(bool); ok && hasIntegrations {
		scores[ToolingIntegration] += 0.6
	}

	// Compliance requirements
	if hasCompliance, ok := context["compliance_required"].(bool); ok && hasCompliance {
		scores[EcosystemGovernance] += 0.7
	}

	return scores
}

// identifyThreats identifies specific threats based on classification
func (c *Classifier) identifyThreats(input ClassificationInput, primary Layer, secondary []Layer) []string {
	threats := make([]string, 0)
	text := strings.ToLower(input.SystemDescription)

	// Add threats from primary layer
	primaryInfo := c.layers[primary]
	for _, threat := range primaryInfo.Threats {
		threatLower := strings.ToLower(threat)
		if strings.Contains(text, threatLower) {
			threats = append(threats, threat)
		}
	}

	// Add threats from secondary layers
	for _, layer := range secondary {
		layerInfo := c.layers[layer]
		for _, threat := range layerInfo.Threats {
			threatLower := strings.ToLower(threat)
			if strings.Contains(text, threatLower) {
				// Check if not already added
				found := false
				for _, existing := range threats {
					if existing == threat {
						found = true
						break
					}
				}
				if !found {
					threats = append(threats, threat)
				}
			}
		}
	}

	// If no specific threats found, add top threats from primary layer
	if len(threats) == 0 && len(primaryInfo.Threats) > 0 {
		// Add top 3 threats from primary layer
		count := 3
		if len(primaryInfo.Threats) < count {
			count = len(primaryInfo.Threats)
		}
		for i := 0; i < count; i++ {
			threats = append(threats, primaryInfo.Threats[i])
		}
	}

	return threats
}

// ExplainClassification generates a human-readable explanation of classification
func (c *Classifier) ExplainClassification(profile *Profile) string {
	var builder strings.Builder

	primaryInfo := c.layers[profile.PrimaryLayer]

	builder.WriteString("🎯 MAESTRO Classification\n")
	builder.WriteString(strings.Repeat("=", 50))
	builder.WriteString("\n\n")

	builder.WriteString("Primary Layer: ")
	builder.WriteString(primaryInfo.FullName)
	builder.WriteString("\n")

	builder.WriteString("  Question: ")
	builder.WriteString(primaryInfo.Question)
	builder.WriteString("\n")

	builder.WriteString("  Confidence: ")
	builder.WriteString(formatFloat(profile.ConfidenceScores[profile.PrimaryLayer], 2))
	builder.WriteString("\n\n")

	if len(profile.SecondaryLayers) > 0 {
		builder.WriteString("Secondary Layers:\n")
		for _, layer := range profile.SecondaryLayers {
			info := c.layers[layer]
			builder.WriteString("  - ")
			builder.WriteString(info.FullName)
			builder.WriteString(" (confidence: ")
			builder.WriteString(formatFloat(profile.ConfidenceScores[layer], 2))
			builder.WriteString(")\n")
		}
		builder.WriteString("\n")
	}

	if len(profile.IdentifiedThreats) > 0 {
		builder.WriteString("Identified Threats:\n")
		for _, threat := range profile.IdentifiedThreats {
			builder.WriteString("  ⚠️  ")
			builder.WriteString(threat)
			builder.WriteString("\n")
		}
		builder.WriteString("\n")
	}

	builder.WriteString("Detection Strategies:\n")
	for _, strategy := range primaryInfo.DetectionStrategies {
		builder.WriteString("  • ")
		builder.WriteString(strategy)
		builder.WriteString("\n")
	}
	builder.WriteString("\n")

	builder.WriteString("Mitigation Strategies:\n")
	for _, strategy := range primaryInfo.MitigationStrategies {
		builder.WriteString("  • ")
		builder.WriteString(strategy)
		builder.WriteString("\n")
	}

	return builder.String()
}

// formatFloat formats a float to specified decimal places
func formatFloat(f float64, decimals int) string {
	multiplier := 1.0
	for i := 0; i < decimals; i++ {
		multiplier *= 10.0
	}
	rounded := int(f*multiplier + 0.5)
	result := float64(rounded) / multiplier

	s := ""
	if result < 0 {
		s = "-"
		result = -result
	}

	intPart := int(result)
	fracPart := result - float64(intPart)

	s += intToString(intPart)

	if decimals > 0 {
		s += "."
		for i := 0; i < decimals; i++ {
			fracPart *= 10
			digit := int(fracPart)
			s += intToString(digit)
			fracPart -= float64(digit)
		}
	}

	return s
}

func intToString(n int) string {
	if n == 0 {
		return "0"
	}

	digits := "0123456789"
	result := ""
	for n > 0 {
		result = string(digits[n%10]) + result
		n /= 10
	}
	return result
}
