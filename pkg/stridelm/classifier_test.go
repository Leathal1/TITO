package stridelm

import (
	"testing"
)

func TestNewClassifier(t *testing.T) {
	c := NewClassifier()
	if c == nil {
		t.Fatal("NewClassifier returned nil")
	}

	if c.categories == nil {
		t.Error("categories map is nil")
	}

	if c.patterns == nil {
		t.Error("patterns map is nil")
	}

	// Check that patterns were compiled for all categories
	expectedCategories := []Category{
		Spoofing, Tampering, Repudiation, InfoDisclosure,
		DenialOfService, Elevation, LateralMovement, Malware,
	}

	for _, cat := range expectedCategories {
		if _, ok := c.patterns[cat]; !ok {
			t.Errorf("no patterns compiled for category %s", cat)
		}
	}
}

func TestClassify_Spoofing(t *testing.T) {
	c := NewClassifier()

	input := ClassificationInput{
		Text:   "Authentication bypass vulnerability allows unauthorized access",
		CVEID:  "CVE-2024-TEST-1",
		CWEIDs: []int{287}, // CWE-287: Improper Authentication
	}

	profile := c.Classify(input)
	if profile == nil {
		t.Fatal("Classify returned nil profile")
	}

	if profile.PrimaryCategory != Spoofing {
		t.Errorf("expected primary category Spoofing, got %s", profile.PrimaryCategory)
	}

	if score, ok := profile.ConfidenceScores[Spoofing]; !ok || score <= 0 {
		t.Errorf("expected positive confidence score for Spoofing, got %v", score)
	}
}

func TestClassify_Tampering(t *testing.T) {
	c := NewClassifier()

	input := ClassificationInput{
		Text:   "SQL injection allows attackers to execute arbitrary SQL commands",
		CVEID:  "CVE-2024-TEST-2",
		CWEIDs: []int{89}, // CWE-89: SQL Injection
	}

	profile := c.Classify(input)
	if profile == nil {
		t.Fatal("Classify returned nil profile")
	}

	if profile.PrimaryCategory != Tampering {
		t.Errorf("expected primary category Tampering, got %s", profile.PrimaryCategory)
	}

	if score, ok := profile.ConfidenceScores[Tampering]; !ok || score <= 0 {
		t.Errorf("expected positive confidence score for Tampering, got %v", score)
	}
}

func TestClassify_InfoDisclosure(t *testing.T) {
	c := NewClassifier()

	input := ClassificationInput{
		Text:   "Sensitive data exposure vulnerability leaks PII through error messages",
		CVEID:  "CVE-2024-TEST-3",
		CWEIDs: []int{200}, // CWE-200: Information Disclosure
	}

	profile := c.Classify(input)
	if profile == nil {
		t.Fatal("Classify returned nil profile")
	}

	if profile.PrimaryCategory != InfoDisclosure {
		t.Errorf("expected primary category InfoDisclosure, got %s", profile.PrimaryCategory)
	}

	if score, ok := profile.ConfidenceScores[InfoDisclosure]; !ok || score <= 0 {
		t.Errorf("expected positive confidence score for InfoDisclosure, got %v", score)
	}
}

func TestClassify_DenialOfService(t *testing.T) {
	c := NewClassifier()

	input := ClassificationInput{
		Text:   "Resource exhaustion DoS vulnerability allows remote attackers to crash the service",
		CVEID:  "CVE-2024-TEST-4",
		CWEIDs: []int{400}, // CWE-400: Uncontrolled Resource Consumption
	}

	profile := c.Classify(input)
	if profile == nil {
		t.Fatal("Classify returned nil profile")
	}

	if profile.PrimaryCategory != DenialOfService {
		t.Errorf("expected primary category DenialOfService, got %s", profile.PrimaryCategory)
	}

	if score, ok := profile.ConfidenceScores[DenialOfService]; !ok || score <= 0 {
		t.Errorf("expected positive confidence score for DenialOfService, got %v", score)
	}
}

func TestClassify_Elevation(t *testing.T) {
	c := NewClassifier()

	input := ClassificationInput{
		Text:   "Privilege escalation vulnerability allows local users to gain root access",
		CVEID:  "CVE-2024-TEST-5",
		CWEIDs: []int{269}, // CWE-269: Improper Privilege Management
	}

	profile := c.Classify(input)
	if profile == nil {
		t.Fatal("Classify returned nil profile")
	}

	if profile.PrimaryCategory != Elevation {
		t.Errorf("expected primary category Elevation, got %s", profile.PrimaryCategory)
	}

	if score, ok := profile.ConfidenceScores[Elevation]; !ok || score <= 0 {
		t.Errorf("expected positive confidence score for Elevation, got %v", score)
	}
}

func TestClassify_Malware(t *testing.T) {
	c := NewClassifier()

	input := ClassificationInput{
		Text:   "Backdoor malware allows remote command and control access to compromised systems",
		CVEID:  "CVE-2024-TEST-6",
		CWEIDs: []int{912}, // CWE-912: Hidden Functionality
	}

	profile := c.Classify(input)
	if profile == nil {
		t.Fatal("Classify returned nil profile")
	}

	if profile.PrimaryCategory != Malware {
		t.Errorf("expected primary category Malware, got %s", profile.PrimaryCategory)
	}

	if score, ok := profile.ConfidenceScores[Malware]; !ok || score <= 0 {
		t.Errorf("expected positive confidence score for Malware, got %v", score)
	}
}

func TestClassify_WithMitreAttack(t *testing.T) {
	c := NewClassifier()

	input := ClassificationInput{
		Text:           "Credential dumping technique",
		MitreAttackIDs: []string{"TA0006"}, // Credential Access tactic
	}

	profile := c.Classify(input)
	if profile == nil {
		t.Fatal("Classify returned nil profile")
	}

	// Should classify as Spoofing based on MITRE ATT&CK tactic
	if profile.PrimaryCategory != Spoofing {
		t.Errorf("expected primary category Spoofing for credential access, got %s", profile.PrimaryCategory)
	}
}

func TestClassify_WithContext(t *testing.T) {
	c := NewClassifier()

	input := ClassificationInput{
		Text: "Vulnerability in authentication module",
		Context: map[string]interface{}{
			"requires_authentication": false,
			"network_accessible":      true,
		},
	}

	profile := c.Classify(input)
	if profile == nil {
		t.Fatal("Classify returned nil profile")
	}

	// Context should boost Spoofing score
	if score, ok := profile.ConfidenceScores[Spoofing]; !ok || score <= 0 {
		t.Errorf("expected positive confidence score for Spoofing with auth context, got %v", score)
	}
}

func TestClassify_SecondaryCategories(t *testing.T) {
	c := NewClassifier()

	input := ClassificationInput{
		Text:   "SQL injection vulnerability that also exposes sensitive data and allows privilege escalation",
		CWEIDs: []int{89, 200, 269}, // SQL injection, info disclosure, privilege escalation
	}

	profile := c.Classify(input)
	if profile == nil {
		t.Fatal("Classify returned nil profile")
	}

	// Should have multiple categories with strong scores
	categoriesWithScore := 0
	for _, score := range profile.ConfidenceScores {
		if score >= 0.3 {
			categoriesWithScore++
		}
	}

	if categoriesWithScore < 2 {
		t.Errorf("expected at least 2 categories with score >= 0.3, got %d", categoriesWithScore)
	}

	if len(profile.SecondaryCategories) == 0 {
		t.Error("expected secondary categories, got none")
	}
}

func TestClassify_EmptyInput(t *testing.T) {
	c := NewClassifier()

	input := ClassificationInput{
		Text: "",
	}

	profile := c.Classify(input)
	if profile == nil {
		t.Fatal("Classify returned nil profile")
	}

	// Should default to InfoDisclosure with minimum score
	if profile.PrimaryCategory == "" {
		t.Error("expected a primary category even with empty input")
	}
}

func TestProfileString(t *testing.T) {
	profile := &Profile{
		PrimaryCategory:     Spoofing,
		SecondaryCategories: []Category{Tampering, InfoDisclosure},
		ConfidenceScores: map[Category]float64{
			Spoofing:       0.9,
			Tampering:      0.5,
			InfoDisclosure: 0.4,
		},
	}

	str := profile.String()
	if str == "" {
		t.Error("String() returned empty string")
	}

	// Should contain primary category
	if str[0] != 'S' {
		t.Errorf("expected string to start with 'S', got %s", str)
	}
}

func TestExplainClassification(t *testing.T) {
	c := NewClassifier()

	input := ClassificationInput{
		Text:   "Authentication bypass vulnerability",
		CWEIDs: []int{287},
	}

	profile := c.Classify(input)
	explanation := c.ExplainClassification(profile)

	if explanation == "" {
		t.Error("ExplainClassification returned empty string")
	}

	// Should contain key sections
	if !contains(explanation, "Primary Category") {
		t.Error("explanation missing 'Primary Category' section")
	}

	if !contains(explanation, "Detection Strategies") {
		t.Error("explanation missing 'Detection Strategies' section")
	}

	if !contains(explanation, "Mitigation Strategies") {
		t.Error("explanation missing 'Mitigation Strategies' section")
	}
}

func TestAllCategories(t *testing.T) {
	categories := AllCategories()

	expectedCount := 8
	if len(categories) != expectedCount {
		t.Errorf("expected %d categories, got %d", expectedCount, len(categories))
	}

	// Check that all expected categories exist
	requiredCategories := []Category{
		Spoofing, Tampering, Repudiation, InfoDisclosure,
		DenialOfService, Elevation, LateralMovement, Malware,
	}

	for _, cat := range requiredCategories {
		info, ok := categories[cat]
		if !ok {
			t.Errorf("category %s not found in AllCategories()", cat)
			continue
		}

		// Validate category info
		if info.Code != cat {
			t.Errorf("category %s has incorrect code: %s", cat, info.Code)
		}

		if info.FullName == "" {
			t.Errorf("category %s has empty FullName", cat)
		}

		if info.Question == "" {
			t.Errorf("category %s has empty Question", cat)
		}

		if len(info.Keywords) == 0 {
			t.Errorf("category %s has no keywords", cat)
		}

		if len(info.DetectionStrategies) == 0 {
			t.Errorf("category %s has no detection strategies", cat)
		}

		if len(info.MitigationStrategies) == 0 {
			t.Errorf("category %s has no mitigation strategies", cat)
		}
	}
}

func TestGetCategoryInfo(t *testing.T) {
	info := GetCategoryInfo(Spoofing)

	if info.Code != Spoofing {
		t.Errorf("expected code Spoofing, got %s", info.Code)
	}

	if info.FullName == "" {
		t.Error("expected non-empty FullName")
	}

	// Test invalid category
	invalidInfo := GetCategoryInfo(Category("INVALID"))
	if invalidInfo.Code != "" {
		t.Error("expected empty CategoryInfo for invalid category")
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
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
