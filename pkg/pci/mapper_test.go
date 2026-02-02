package pci

import (
	"os"
	"testing"

	"github.com/Leathal1/TITO/v2/pkg/stridelm"
)

func TestMain(m *testing.M) {
	// Set skip license for testing
	os.Setenv("TITO_SKIP_LICENSE", "1")
	code := m.Run()
	os.Unsetenv("TITO_SKIP_LICENSE")
	os.Exit(code)
}

func TestMapBySTRIDE(t *testing.T) {
	mapper := NewMapper()

	tests := []struct {
		name             string
		category         stridelm.Category
		expectedReqs     []string
		expectedSubReqs  []string
		minConfidence    float64
	}{
		{
			name:            "Spoofing maps to authentication",
			category:        stridelm.Spoofing,
			expectedReqs:    []string{"8"},
			expectedSubReqs: []string{"8.2.1", "8.3.1"},
			minConfidence:   0.7,
		},
		{
			name:            "Tampering maps to secure development",
			category:        stridelm.Tampering,
			expectedReqs:    []string{"6", "10"},
			expectedSubReqs: []string{"6.2.4"},
			minConfidence:   0.7,
		},
		{
			name:            "InfoDisclosure maps to data protection",
			category:        stridelm.InfoDisclosure,
			expectedReqs:    []string{"3", "4", "7"},
			expectedSubReqs: []string{"3.5.1", "4.2.1"},
			minConfidence:   0.7,
		},
		{
			name:            "Repudiation maps to logging",
			category:        stridelm.Repudiation,
			expectedReqs:    []string{"10"},
			expectedSubReqs: []string{"10.2.1", "10.3.1"},
			minConfidence:   0.8,
		},
		{
			name:            "Elevation maps to access control",
			category:        stridelm.Elevation,
			expectedReqs:    []string{"7", "8"},
			expectedSubReqs: []string{"7.2.2", "8.2.1"},
			minConfidence:   0.7,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mappings := mapper.mapBySTRIDE(tt.category)

			if len(mappings) == 0 {
				t.Errorf("Expected mappings for %s, got none", tt.category)
				return
			}

			// Check that expected requirements are present
			foundReqs := make(map[string]bool)
			foundSubReqs := make(map[string]bool)
			
			for _, mapping := range mappings {
				foundReqs[mapping.RequirementID] = true
				foundSubReqs[mapping.SubRequirementID] = true

				if mapping.Confidence < tt.minConfidence {
					t.Errorf("Confidence too low: got %.2f, want >= %.2f", 
						mapping.Confidence, tt.minConfidence)
				}
			}

			// Verify expected requirements are found
			for _, reqID := range tt.expectedReqs {
				if !foundReqs[reqID] {
					t.Errorf("Expected requirement %s not found in mappings", reqID)
				}
			}

			// Verify expected sub-requirements are found
			for _, subReqID := range tt.expectedSubReqs {
				if !foundSubReqs[subReqID] {
					t.Errorf("Expected sub-requirement %s not found in mappings", subReqID)
				}
			}
		})
	}
}

func TestMapByCWE(t *testing.T) {
	mapper := NewMapper()

	tests := []struct {
		name            string
		cweIDs          []string
		expectedReqs    []string
		expectedSubReqs []string
	}{
		{
			name:            "SQL Injection CWE maps to secure coding",
			cweIDs:          []string{"CWE-89"},
			expectedReqs:    []string{"6"},
			expectedSubReqs: []string{"6.2.4", "6.4.1"},
		},
		{
			name:            "Hardcoded credentials maps to authentication",
			cweIDs:          []string{"CWE-798"},
			expectedReqs:    []string{"8", "3"},
			expectedSubReqs: []string{"8.2.1", "3.6.1"},
		},
		{
			name:            "Weak crypto maps to encryption requirements",
			cweIDs:          []string{"CWE-327"},
			expectedReqs:    []string{"4", "3"},
			expectedSubReqs: []string{"4.2.1", "3.5.1"},
		},
		{
			name:            "Access control issues map to requirement 7",
			cweIDs:          []string{"CWE-284"},
			expectedReqs:    []string{"7"},
			expectedSubReqs: []string{"7.2.1", "7.3.1"},
		},
		{
			name:            "Sensitive data exposure maps to data protection",
			cweIDs:          []string{"CWE-200"},
			expectedReqs:    []string{"3", "10"},
			expectedSubReqs: []string{"3.3.1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mappings := mapper.mapByCWE(tt.cweIDs)

			if len(mappings) == 0 {
				t.Errorf("Expected mappings for CWEs %v, got none", tt.cweIDs)
				return
			}

			foundReqs := make(map[string]bool)
			foundSubReqs := make(map[string]bool)
			
			for _, mapping := range mappings {
				foundReqs[mapping.RequirementID] = true
				foundSubReqs[mapping.SubRequirementID] = true
			}

			for _, reqID := range tt.expectedReqs {
				if !foundReqs[reqID] {
					t.Errorf("Expected requirement %s not found", reqID)
				}
			}

			for _, subReqID := range tt.expectedSubReqs {
				if !foundSubReqs[subReqID] {
					t.Errorf("Expected sub-requirement %s not found", subReqID)
				}
			}
		})
	}
}

func TestMapByKeywords(t *testing.T) {
	mapper := NewMapper()

	tests := []struct {
		name            string
		text            string
		expectedReqs    []string
		expectedSubReqs []string
		minMappings     int
	}{
		{
			name:            "SQL injection keyword",
			text:            "SQL injection vulnerability in user input",
			expectedReqs:    []string{"6"},
			expectedSubReqs: []string{"6.2.4", "6.4.1"},
			minMappings:     2,
		},
		{
			name:            "Hardcoded credentials keyword",
			text:            "Hardcoded password found in source code",
			expectedReqs:    []string{"8", "2", "3"},
			expectedSubReqs: []string{"8.2.1", "2.2.2"},
			minMappings:     3,
		},
		{
			name:            "Weak crypto keyword",
			text:            "Weak encryption using MD5 algorithm",
			expectedReqs:    []string{"4", "3"},
			expectedSubReqs: []string{"4.2.1", "3.5.1"},
			minMappings:     2,
		},
		{
			name:            "Missing authentication keyword",
			text:            "API endpoint missing authentication",
			expectedReqs:    []string{"8", "7"},
			expectedSubReqs: []string{"8.2.1", "7.2.1"},
			minMappings:     2,
		},
		{
			name:            "Logging issue keyword",
			text:            "Insufficient logging of access attempts",
			expectedReqs:    []string{"10"},
			expectedSubReqs: []string{"10.2.1", "10.3.1"},
			minMappings:     2,
		},
		{
			name:            "Cardholder data keyword",
			text:            "PAN stored without encryption",
			expectedReqs:    []string{"3"},
			expectedSubReqs: []string{"3.5.1", "3.2.1"},
			minMappings:     2,
		},
		{
			name:            "MFA missing keyword",
			text:            "Missing MFA for admin access",
			expectedReqs:    []string{"8"},
			expectedSubReqs: []string{"8.3.1", "8.4.2"},
			minMappings:     2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mappings := mapper.mapByKeywords(tt.text)

			if len(mappings) < tt.minMappings {
				t.Errorf("Expected at least %d mappings, got %d", tt.minMappings, len(mappings))
				return
			}

			foundReqs := make(map[string]bool)
			foundSubReqs := make(map[string]bool)
			
			for _, mapping := range mappings {
				foundReqs[mapping.RequirementID] = true
				foundSubReqs[mapping.SubRequirementID] = true
			}

			for _, reqID := range tt.expectedReqs {
				if !foundReqs[reqID] {
					t.Errorf("Expected requirement %s not found", reqID)
				}
			}

			for _, subReqID := range tt.expectedSubReqs {
				if !foundSubReqs[subReqID] {
					t.Errorf("Expected sub-requirement %s not found", subReqID)
				}
			}
		})
	}
}

func TestMapThreat(t *testing.T) {
	mapper := NewMapper()

	tests := []struct {
		name           string
		title          string
		description    string
		strideCategory stridelm.Category
		cweIDs         []string
		expectedCount  int
	}{
		{
			name:           "SQL injection threat",
			title:          "SQL Injection in Login Form",
			description:    "User input not validated, allowing SQL injection attacks",
			strideCategory: stridelm.Tampering,
			cweIDs:         []string{"CWE-89"},
			expectedCount:  2, // Should map to at least 2 requirements
		},
		{
			name:           "Hardcoded credential threat",
			title:          "Hardcoded API Key",
			description:    "API key hardcoded in source code",
			strideCategory: stridelm.Spoofing,
			cweIDs:         []string{"CWE-798"},
			expectedCount:  3, // STRIDE + CWE + keyword mappings
		},
		{
			name:           "Info disclosure threat",
			title:          "Sensitive Data Exposure",
			description:    "Cardholder data exposed in logs",
			strideCategory: stridelm.InfoDisclosure,
			cweIDs:         []string{"CWE-532"},
			expectedCount:  2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mappings := mapper.MapThreat(
				tt.title,
				tt.description,
				tt.strideCategory,
				tt.cweIDs,
				[]string{},
			)

			if len(mappings) < tt.expectedCount {
				t.Errorf("Expected at least %d mappings, got %d", tt.expectedCount, len(mappings))
			}

			// Verify all mappings have valid confidence scores
			for _, mapping := range mappings {
				if mapping.Confidence < 0.0 || mapping.Confidence > 1.0 {
					t.Errorf("Invalid confidence score: %.2f", mapping.Confidence)
				}

				if mapping.Reason == "" {
					t.Error("Mapping should have a reason")
				}
			}
		})
	}
}

func TestDeduplicate(t *testing.T) {
	mapper := NewMapper()

	// Create duplicate mappings
	mappings := []Mapping{
		{
			RequirementID:    "6",
			SubRequirementID: "6.2.4",
			Confidence:       0.8,
			Reason:           "SQL injection",
		},
		{
			RequirementID:    "6",
			SubRequirementID: "6.2.4",
			Confidence:       0.9, // Higher confidence
			Reason:           "Input validation required",
		},
		{
			RequirementID:    "8",
			SubRequirementID: "8.2.1",
			Confidence:       0.85,
			Reason:           "Authentication",
		},
	}

	deduplicated := mapper.deduplicate(mappings)

	if len(deduplicated) != 2 {
		t.Errorf("Expected 2 unique mappings, got %d", len(deduplicated))
	}

	// Find the deduplicated 6.2.4 mapping
	var found624 *Mapping
	for i := range deduplicated {
		if deduplicated[i].SubRequirementID == "6.2.4" {
			found624 = &deduplicated[i]
			break
		}
	}

	if found624 == nil {
		t.Fatal("Deduplicated mapping for 6.2.4 not found")
	}

	// Should keep the higher confidence
	if found624.Confidence != 0.9 {
		t.Errorf("Expected confidence 0.9, got %.2f", found624.Confidence)
	}

	// Should combine reasons
	if len(found624.Reason) < 10 {
		t.Error("Expected combined reason to be longer")
	}
}

func TestGetRequirementDetails(t *testing.T) {
	mapper := NewMapper()

	mapping := Mapping{
		RequirementID:    "6",
		SubRequirementID: "6.2.4",
		Confidence:       0.9,
		Reason:           "Test",
	}

	req, subReq := mapper.GetRequirementDetails(mapping)

	if req == nil {
		t.Fatal("Expected requirement, got nil")
	}

	if req.ID != "6" {
		t.Errorf("Expected requirement ID 6, got %s", req.ID)
	}

	if subReq == nil {
		t.Fatal("Expected sub-requirement, got nil")
	}

	if subReq.ID != "6.2.4" {
		t.Errorf("Expected sub-requirement ID 6.2.4, got %s", subReq.ID)
	}
}

func TestMapBySemgrepRules(t *testing.T) {
	mapper := NewMapper()

	tests := []struct {
		name         string
		ruleIDs      []string
		expectedReqs []string
		minMappings  int
	}{
		{
			name:         "PCI cardholder rule",
			ruleIDs:      []string{"pci-cardholder-data-exposure"},
			expectedReqs: []string{"3"},
			minMappings:  1,
		},
		{
			name:         "PCI crypto rule",
			ruleIDs:      []string{"pci-crypto-weak-algorithm"},
			expectedReqs: []string{"4"},
			minMappings:  1,
		},
		{
			name:         "SQL injection rule",
			ruleIDs:      []string{"sql-injection-detected"},
			expectedReqs: []string{"6"},
			minMappings:  1,
		},
		{
			name:         "Hardcoded secret rule",
			ruleIDs:      []string{"hardcoded-api-key"},
			expectedReqs: []string{"8"},
			minMappings:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mappings := mapper.mapBySemgrepRules(tt.ruleIDs)

			if len(mappings) < tt.minMappings {
				t.Errorf("Expected at least %d mappings, got %d", tt.minMappings, len(mappings))
			}

			foundReqs := make(map[string]bool)
			for _, mapping := range mappings {
				foundReqs[mapping.RequirementID] = true
			}

			for _, reqID := range tt.expectedReqs {
				if !foundReqs[reqID] {
					t.Errorf("Expected requirement %s not found", reqID)
				}
			}
		})
	}
}
