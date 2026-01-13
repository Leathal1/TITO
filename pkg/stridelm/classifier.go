package stridelm

import (
	"regexp"
	"strings"
)

// Profile represents a STRIDE-LM classification profile for a specific threat
type Profile struct {
	PrimaryCategory     Category            `json:"primary_category" yaml:"primary_category"`
	SecondaryCategories []Category          `json:"secondary_categories" yaml:"secondary_categories"`
	ConfidenceScores    map[Category]float64 `json:"confidence_scores" yaml:"confidence_scores"`
}

// String returns a human-readable representation
func (p *Profile) String() string {
	result := string(p.PrimaryCategory)
	if len(p.SecondaryCategories) > 0 {
		var secondary []string
		for _, cat := range p.SecondaryCategories {
			secondary = append(secondary, string(cat))
		}
		result += "(" + strings.Join(secondary, "") + ")"
	}
	return result
}

// Classifier performs STRIDE-LM classification
type Classifier struct {
	categories map[Category]CategoryInfo
	patterns   map[Category][]*regexp.Regexp
}

// NewClassifier creates a new STRIDE-LM classifier
func NewClassifier() *Classifier {
	c := &Classifier{
		categories: AllCategories(),
		patterns:   make(map[Category][]*regexp.Regexp),
	}

	// Compile regex patterns for each category
	for cat, info := range c.categories {
		var patterns []*regexp.Regexp
		for _, keyword := range info.Keywords {
			// Match whole words, case insensitive
			pattern := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(keyword) + `\b`)
			patterns = append(patterns, pattern)
		}
		c.patterns[cat] = patterns
	}

	return c
}

// ClassificationInput holds input data for classification
type ClassificationInput struct {
	Text            string
	CVEID           string
	CWEIDs          []int
	MitreAttackIDs  []string
	Context         map[string]interface{}
}

// Classify classifies a threat into STRIDE-LM categories
func (c *Classifier) Classify(input ClassificationInput) *Profile {
	// Calculate confidence scores for each category
	scores := c.calculateScores(input)

	// Sort categories by score to determine primary and secondary
	var sortedCategories []Category
	for cat := range scores {
		sortedCategories = append(sortedCategories, cat)
	}

	// Simple bubble sort by score (descending)
	for i := 0; i < len(sortedCategories); i++ {
		for j := i + 1; j < len(sortedCategories); j++ {
			if scores[sortedCategories[i]] < scores[sortedCategories[j]] {
				sortedCategories[i], sortedCategories[j] = sortedCategories[j], sortedCategories[i]
			}
		}
	}

	// Primary category is the highest scoring
	primaryCategory := sortedCategories[0]

	// Secondary categories are those with score > threshold
	secondaryThreshold := 0.3
	var secondaryCategories []Category
	for i := 1; i < len(sortedCategories); i++ {
		cat := sortedCategories[i]
		if scores[cat] >= secondaryThreshold {
			secondaryCategories = append(secondaryCategories, cat)
		}
	}

	return &Profile{
		PrimaryCategory:     primaryCategory,
		SecondaryCategories: secondaryCategories,
		ConfidenceScores:    scores,
	}
}

// calculateScores calculates confidence scores for each STRIDE-LM category
func (c *Classifier) calculateScores(input ClassificationInput) map[Category]float64 {
	scores := make(map[Category]float64)

	// Initialize all categories with 0.0
	for cat := range c.categories {
		scores[cat] = 0.0
	}

	// Signal 1: Keyword matching (weight: 0.4)
	keywordScores := c.scoreKeywords(input.Text)
	for cat, score := range keywordScores {
		scores[cat] += 0.4 * score
	}

	// Signal 2: CWE ID mapping (weight: 0.3)
	if len(input.CWEIDs) > 0 {
		cweScores := c.scoreCWEIDs(input.CWEIDs)
		for cat, score := range cweScores {
			scores[cat] += 0.3 * score
		}
	}

	// Signal 3: MITRE ATT&CK mapping (weight: 0.2)
	if len(input.MitreAttackIDs) > 0 {
		attackScores := c.scoreMitreAttack(input.MitreAttackIDs)
		for cat, score := range attackScores {
			scores[cat] += 0.2 * score
		}
	}

	// Signal 4: Contextual heuristics (weight: 0.1)
	if input.Context != nil {
		contextScores := c.scoreContext(input.Context)
		for cat, score := range contextScores {
			scores[cat] += 0.1 * score
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
		for cat := range scores {
			scores[cat] = scores[cat] / maxScore
		}
	}

	// Ensure at least one category has a minimum score
	allLow := true
	for _, score := range scores {
		if score >= 0.1 {
			allLow = false
			break
		}
	}
	if allLow {
		// Default to InfoDisclosure for unknown threats
		scores[InfoDisclosure] = 0.5
	}

	return scores
}

// scoreKeywords scores categories based on keyword matches
func (c *Classifier) scoreKeywords(text string) map[Category]float64 {
	scores := make(map[Category]float64)

	for cat, patterns := range c.patterns {
		matches := 0
		for _, pattern := range patterns {
			if pattern.MatchString(text) {
				matches++
			}
		}

		// Score is proportional to number of keyword matches
		// Multiple matches increase confidence
		if matches > 0 {
			score := float64(matches) / 3.0 // Cap at 3 matches
			if score > 1.0 {
				score = 1.0
			}
			scores[cat] = score
		} else {
			scores[cat] = 0.0
		}
	}

	return scores
}

// scoreCWEIDs scores categories based on CWE ID mappings
func (c *Classifier) scoreCWEIDs(cweIDs []int) map[Category]float64 {
	scores := make(map[Category]float64)

	// Initialize all scores to 0
	for cat := range c.categories {
		scores[cat] = 0.0
	}

	// Check each CWE ID against category mappings
	for cat, info := range c.categories {
		for _, inputCWE := range cweIDs {
			for _, catCWE := range info.CWEIDs {
				if inputCWE == catCWE {
					// Strong signal - CWE IDs are authoritative
					scores[cat] = 1.0
					break
				}
			}
		}
	}

	return scores
}

// scoreMitreAttack scores categories based on MITRE ATT&CK technique mappings
func (c *Classifier) scoreMitreAttack(mitreAttackIDs []string) map[Category]float64 {
	scores := make(map[Category]float64)

	// Initialize all scores to 0
	for cat := range c.categories {
		scores[cat] = 0.0
	}

	// Map ATT&CK tactics to STRIDE-LM categories
	tacticMapping := map[string]Category{
		"TA0001": Spoofing,        // Initial Access
		"TA0002": Malware,          // Execution
		"TA0003": Malware,          // Persistence
		"TA0004": Elevation,        // Privilege Escalation
		"TA0005": Tampering,        // Defense Evasion
		"TA0006": Spoofing,         // Credential Access
		"TA0007": LateralMovement,  // Discovery
		"TA0008": LateralMovement,  // Lateral Movement
		"TA0009": InfoDisclosure,   // Collection
		"TA0010": InfoDisclosure,   // Exfiltration
		"TA0011": Malware,          // Command and Control
		"TA0040": DenialOfService,  // Impact
	}

	for _, attackID := range mitreAttackIDs {
		// Check if it's a tactic ID (TA prefix)
		if strings.HasPrefix(attackID, "TA") {
			if cat, ok := tacticMapping[attackID]; ok {
				scores[cat] = 0.8
			}
		}
	}

	return scores
}

// scoreContext scores categories based on contextual information
func (c *Classifier) scoreContext(context map[string]interface{}) map[Category]float64 {
	scores := make(map[Category]float64)

	// Initialize all scores to 0
	for cat := range c.categories {
		scores[cat] = 0.0
	}

	// Authentication-related context
	if requiresAuth, ok := context["requires_authentication"].(bool); ok && !requiresAuth {
		scores[Spoofing] += 0.5
	}

	// Network-related context
	if networkAccessible, ok := context["network_accessible"].(bool); ok && networkAccessible {
		scores[LateralMovement] += 0.3
	}

	// Data exposure context
	if dataExposure, ok := context["data_exposure"].(bool); ok && dataExposure {
		scores[InfoDisclosure] += 0.7
	}

	// Service disruption context
	if affectsAvailability, ok := context["affects_availability"].(bool); ok && affectsAvailability {
		scores[DenialOfService] += 0.6
	}

	// Privilege context
	if privEsc, ok := context["privilege_escalation"].(bool); ok && privEsc {
		scores[Elevation] += 0.8
	}

	return scores
}

// ExplainClassification generates a human-readable explanation of classification
func (c *Classifier) ExplainClassification(profile *Profile) string {
	var builder strings.Builder

	primaryInfo := c.categories[profile.PrimaryCategory]

	builder.WriteString("Primary Category: ")
	builder.WriteString(primaryInfo.FullName)
	builder.WriteString("\n")

	builder.WriteString("  Question: ")
	builder.WriteString(primaryInfo.Question)
	builder.WriteString("\n")

	builder.WriteString("  Confidence: ")
	builder.WriteString(formatFloat(profile.ConfidenceScores[profile.PrimaryCategory], 2))
	builder.WriteString("\n\n")

	if len(profile.SecondaryCategories) > 0 {
		builder.WriteString("Secondary Categories:\n")
		for _, cat := range profile.SecondaryCategories {
			info := c.categories[cat]
			builder.WriteString("  - ")
			builder.WriteString(info.FullName)
			builder.WriteString(" (confidence: ")
			builder.WriteString(formatFloat(profile.ConfidenceScores[cat], 2))
			builder.WriteString(")\n")
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
	// Simple implementation - multiply by 10^decimals, round, divide back
	multiplier := 1.0
	for i := 0; i < decimals; i++ {
		multiplier *= 10.0
	}
	rounded := int(f*multiplier + 0.5)
	result := float64(rounded) / multiplier

	// Convert to string with basic formatting
	s := ""
	if result < 0 {
		s = "-"
		result = -result
	}

	intPart := int(result)
	fracPart := result - float64(intPart)

	s += intToString(intPart)

	if decimals > 0 && fracPart > 0 {
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
