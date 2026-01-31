package semgrep

import (
	"context"
	"encoding/json"
	"testing"
)

func TestNewRunner(t *testing.T) {
	runner := NewRunner("")
	if runner == nil {
		t.Fatal("NewRunner returned nil")
	}

	if runner.config != "auto" {
		t.Errorf("Expected default config 'auto', got '%s'", runner.config)
	}

	runner2 := NewRunner("p/security-audit")
	if runner2.config != "p/security-audit" {
		t.Errorf("Expected config 'p/security-audit', got '%s'", runner2.config)
	}
}

func TestFilterByConfidence(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "test1",
			Extra: Extra{
				Metadata: Metadata{
					Confidence: "HIGH",
				},
			},
		},
		{
			CheckID: "test2",
			Extra: Extra{
				Metadata: Metadata{
					Confidence: "MEDIUM",
				},
			},
		},
		{
			CheckID: "test3",
			Extra: Extra{
				Metadata: Metadata{
					Confidence: "LOW",
				},
			},
		},
	}

	// Filter for HIGH confidence
	filtered := FilterByConfidence(findings, ConfidenceHigh)
	if len(filtered) != 1 {
		t.Errorf("Expected 1 HIGH confidence finding, got %d", len(filtered))
	}

	// Filter for MEDIUM and above
	filtered = FilterByConfidence(findings, ConfidenceMedium)
	if len(filtered) != 2 {
		t.Errorf("Expected 2 MEDIUM+ confidence findings, got %d", len(filtered))
	}

	// No filter
	filtered = FilterByConfidence(findings, "")
	if len(filtered) != 3 {
		t.Errorf("Expected all 3 findings with no filter, got %d", len(filtered))
	}
}

func TestFilterBySeverity(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "test1",
			Extra: Extra{
				Severity: "ERROR",
			},
		},
		{
			CheckID: "test2",
			Extra: Extra{
				Severity: "WARNING",
			},
		},
		{
			CheckID: "test3",
			Extra: Extra{
				Severity: "INFO",
			},
		},
	}

	// Filter for ERROR severity
	filtered := FilterBySeverity(findings, SeverityError)
	if len(filtered) != 1 {
		t.Errorf("Expected 1 ERROR severity finding, got %d", len(filtered))
	}

	// Filter for WARNING and above
	filtered = FilterBySeverity(findings, SeverityWarning)
	if len(filtered) != 2 {
		t.Errorf("Expected 2 WARNING+ severity findings, got %d", len(filtered))
	}

	// No filter
	filtered = FilterBySeverity(findings, "")
	if len(filtered) != 3 {
		t.Errorf("Expected all 3 findings with no filter, got %d", len(filtered))
	}
}

func TestGetCWEIDs(t *testing.T) {
	finding := Finding{
		Extra: Extra{
			Metadata: Metadata{
				CWE: []string{"CWE-79", "CWE-89", "20"},
			},
		},
	}

	cweIDs := GetCWEIDs(finding)

	if len(cweIDs) != 3 {
		t.Fatalf("Expected 3 CWE IDs, got %d", len(cweIDs))
	}

	expected := map[int]bool{79: true, 89: true, 20: true}
	for _, id := range cweIDs {
		if !expected[id] {
			t.Errorf("Unexpected CWE ID: %d", id)
		}
	}
}

func TestGetSummaryStats(t *testing.T) {
	findings := []Finding{
		{
			CheckID: "rule1",
			Extra: Extra{
				Severity: "ERROR",
				Metadata: Metadata{
					Confidence: "HIGH",
					CWE:        []string{"CWE-79"},
				},
			},
		},
		{
			CheckID: "rule1",
			Extra: Extra{
				Severity: "ERROR",
				Metadata: Metadata{
					Confidence: "HIGH",
					CWE:        []string{"CWE-79", "CWE-89"},
				},
			},
		},
		{
			CheckID: "rule2",
			Extra: Extra{
				Severity: "WARNING",
				Metadata: Metadata{
					Confidence: "MEDIUM",
					CWE:        []string{"CWE-20"},
				},
			},
		},
	}

	stats := GetSummaryStats(findings)

	if stats.TotalFindings != 3 {
		t.Errorf("Expected 3 total findings, got %d", stats.TotalFindings)
	}

	if stats.BySeverity[SeverityError] != 2 {
		t.Errorf("Expected 2 ERROR findings, got %d", stats.BySeverity[SeverityError])
	}

	if stats.BySeverity[SeverityWarning] != 1 {
		t.Errorf("Expected 1 WARNING finding, got %d", stats.BySeverity[SeverityWarning])
	}

	if stats.ByConfidence[ConfidenceHigh] != 2 {
		t.Errorf("Expected 2 HIGH confidence findings, got %d", stats.ByConfidence[ConfidenceHigh])
	}

	if stats.UniqueRules != 2 {
		t.Errorf("Expected 2 unique rules, got %d", stats.UniqueRules)
	}

	if stats.UniqueCWEs != 3 {
		t.Errorf("Expected 3 unique CWEs, got %d", stats.UniqueCWEs)
	}
}

func TestSemgrepOutputParsing(t *testing.T) {
	// Mock Semgrep JSON output
	mockJSON := `{
		"results": [
			{
				"check_id": "test.sql-injection",
				"path": "app.py",
				"start": {"line": 10, "col": 5, "offset": 100},
				"end": {"line": 10, "col": 20, "offset": 115},
				"extra": {
					"message": "SQL injection vulnerability",
					"severity": "ERROR",
					"metadata": {
						"category": "security",
						"confidence": "HIGH",
						"cwe": ["CWE-89"],
						"owasp": ["A03:2021"]
					},
					"lines": "cursor.execute(query)",
					"fingerprint": "abc123"
				}
			}
		],
		"errors": []
	}`

	var output SemgrepOutput
	err := json.Unmarshal([]byte(mockJSON), &output)
	if err != nil {
		t.Fatalf("Failed to parse mock JSON: %v", err)
	}

	if len(output.Results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(output.Results))
	}

	finding := output.Results[0]

	if finding.CheckID != "test.sql-injection" {
		t.Errorf("Expected check_id 'test.sql-injection', got '%s'", finding.CheckID)
	}

	if finding.Path != "app.py" {
		t.Errorf("Expected path 'app.py', got '%s'", finding.Path)
	}

	if finding.Extra.Severity != "ERROR" {
		t.Errorf("Expected severity 'ERROR', got '%s'", finding.Extra.Severity)
	}

	if len(finding.Extra.Metadata.CWE) != 1 || finding.Extra.Metadata.CWE[0] != "CWE-89" {
		t.Errorf("Expected CWE ['CWE-89'], got %v", finding.Extra.Metadata.CWE)
	}
}

// TestCheckInstalled would require semgrep to be installed
// Skipping to avoid test failures on systems without semgrep
func TestCheckInstalled_Skip(t *testing.T) {
	t.Skip("Skipping check installed test - requires semgrep installation")

	runner := NewRunner("")
	ctx := context.Background()
	err := runner.checkInstalled(ctx)
	if err != nil {
		t.Logf("Semgrep not installed (expected on some systems): %v", err)
	}
}
