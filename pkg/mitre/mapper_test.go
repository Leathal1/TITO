package mitre

import (
	"testing"

	"github.com/Leathal1/TITO/pkg/maestro"
	"github.com/Leathal1/TITO/pkg/stridelm"
)

func TestNewMapper(t *testing.T) {
	mapper := NewMapper()
	if mapper == nil {
		t.Fatal("NewMapper returned nil")
	}

	if len(mapper.techniques) == 0 {
		t.Error("Expected techniques to be loaded")
	}
}

func TestMapSTRIDELM_Spoofing(t *testing.T) {
	mapper := NewMapper()
	mappings := mapper.MapSTRIDELM(stridelm.Spoofing, 0.9)

	if len(mappings) == 0 {
		t.Fatal("Expected mappings for Spoofing category")
	}

	// Should map to credential access techniques
	foundValidAccounts := false
	for _, mapping := range mappings {
		if mapping.TechniqueID == "T1078" { // Valid Accounts
			foundValidAccounts = true
			if mapping.Confidence <= 0 {
				t.Error("Expected positive confidence for Valid Accounts mapping")
			}
		}
	}

	if !foundValidAccounts {
		t.Error("Expected mapping to T1078 (Valid Accounts) for Spoofing")
	}
}

func TestMapSTRIDELM_InfoDisclosure(t *testing.T) {
	mapper := NewMapper()
	mappings := mapper.MapSTRIDELM(stridelm.InfoDisclosure, 0.8)

	if len(mappings) == 0 {
		t.Fatal("Expected mappings for Information Disclosure category")
	}

	// Should map to collection and exfiltration techniques
	foundCollection := false
	for _, mapping := range mappings {
		if mapping.TechniqueID == "T1005" || // Data from Local System
			mapping.TechniqueID == "T1041" || // Exfiltration Over C2
			mapping.TechniqueID == "T1567" { // Exfiltration Over Web Service
			foundCollection = true
			break
		}
	}

	if !foundCollection {
		t.Error("Expected mapping to collection/exfiltration techniques")
	}
}

func TestMapSTRIDELM_DenialOfService(t *testing.T) {
	mapper := NewMapper()
	mappings := mapper.MapSTRIDELM(stridelm.DenialOfService, 0.95)

	if len(mappings) == 0 {
		t.Fatal("Expected mappings for Denial of Service category")
	}

	// Should map to DoS impact technique
	foundDoS := false
	for _, mapping := range mappings {
		if mapping.TechniqueID == "T1499" { // Endpoint Denial of Service
			foundDoS = true
			if mapping.Confidence < 0.8 {
				t.Errorf("Expected high confidence for DoS mapping, got %.2f", mapping.Confidence)
			}
		}
	}

	if !foundDoS {
		t.Error("Expected mapping to T1499 (Endpoint Denial of Service)")
	}
}

func TestMapMAESTRO_FoundationModels(t *testing.T) {
	mapper := NewMapper()
	mappings := mapper.MapMAESTRO(maestro.FoundationModels, 0.9)

	if len(mappings) == 0 {
		t.Fatal("Expected mappings for Foundation Models layer")
	}

	// Should include execution and exploitation techniques
	foundExecution := false
	for _, mapping := range mappings {
		if mapping.TechniqueID == "T1059" || // Command and Scripting Interpreter
			mapping.TechniqueID == "T1190" { // Exploit Public-Facing Application
			foundExecution = true
			break
		}
	}

	if !foundExecution {
		t.Error("Expected mapping to execution/exploitation techniques")
	}
}

func TestMapMAESTRO_DataKnowledge(t *testing.T) {
	mapper := NewMapper()
	mappings := mapper.MapMAESTRO(maestro.DataKnowledge, 0.8)

	if len(mappings) == 0 {
		t.Fatal("Expected mappings for Data & Knowledge layer")
	}

	// Should map to data manipulation
	foundManipulation := false
	for _, mapping := range mappings {
		if mapping.TechniqueID == "T1565" { // Data Manipulation
			foundManipulation = true
			if mapping.Confidence < 0.6 {
				t.Errorf("Expected high confidence for Data Manipulation, got %.2f", mapping.Confidence)
			}
		}
	}

	if !foundManipulation {
		t.Error("Expected mapping to T1565 (Data Manipulation)")
	}
}

func TestMapMAESTRO_ToolingIntegration(t *testing.T) {
	mapper := NewMapper()
	mappings := mapper.MapMAESTRO(maestro.ToolingIntegration, 0.85)

	if len(mappings) == 0 {
		t.Fatal("Expected mappings for Tooling & Integration layer")
	}

	// Should map to credential access
	foundCreds := false
	for _, mapping := range mappings {
		if mapping.TechniqueID == "T1555" { // Credentials from Password Stores
			foundCreds = true
		}
	}

	if !foundCreds {
		t.Error("Expected mapping to credential access techniques")
	}
}

func TestMapMAESTRO_DeploymentInfra(t *testing.T) {
	mapper := NewMapper()
	mappings := mapper.MapMAESTRO(maestro.DeploymentInfra, 0.9)

	if len(mappings) == 0 {
		t.Fatal("Expected mappings for Deployment & Infrastructure layer")
	}

	// Should map to privilege escalation
	foundPrivEsc := false
	for _, mapping := range mappings {
		if mapping.TechniqueID == "T1068" { // Exploitation for Privilege Escalation
			foundPrivEsc = true
		}
	}

	if !foundPrivEsc {
		t.Error("Expected mapping to privilege escalation techniques")
	}
}

func TestEnrichThreat_STRIDEOnly(t *testing.T) {
	mapper := NewMapper()

	strideProfile := &stridelm.Profile{
		PrimaryCategory: stridelm.Spoofing,
		ConfidenceScores: map[stridelm.Category]float64{
			stridelm.Spoofing: 0.9,
		},
	}

	enriched := mapper.EnrichThreat(strideProfile, nil)

	if len(enriched) == 0 {
		t.Fatal("Expected enriched threat mappings")
	}

	// Should have credential access techniques
	if _, ok := enriched["T1078"]; !ok {
		t.Error("Expected T1078 (Valid Accounts) in enriched threat")
	}
}

func TestEnrichThreat_MAESTROOnly(t *testing.T) {
	mapper := NewMapper()

	maestroProfile := &maestro.Profile{
		PrimaryLayer: maestro.FoundationModels,
		ConfidenceScores: map[maestro.Layer]float64{
			maestro.FoundationModels: 0.85,
		},
	}

	enriched := mapper.EnrichThreat(nil, maestroProfile)

	if len(enriched) == 0 {
		t.Fatal("Expected enriched threat mappings")
	}
}

func TestEnrichThreat_Combined(t *testing.T) {
	mapper := NewMapper()

	strideProfile := &stridelm.Profile{
		PrimaryCategory:     stridelm.InfoDisclosure,
		SecondaryCategories: []stridelm.Category{stridelm.Tampering},
		ConfidenceScores: map[stridelm.Category]float64{
			stridelm.InfoDisclosure: 0.9,
			stridelm.Tampering:      0.6,
		},
	}

	maestroProfile := &maestro.Profile{
		PrimaryLayer: maestro.DataKnowledge,
		ConfidenceScores: map[maestro.Layer]float64{
			maestro.DataKnowledge: 0.8,
		},
	}

	enriched := mapper.EnrichThreat(strideProfile, maestroProfile)

	if len(enriched) == 0 {
		t.Fatal("Expected enriched threat mappings from both profiles")
	}

	// Should have mappings from both STRIDE-LM and MAESTRO
	// InfoDisclosure maps to collection/exfiltration
	// DataKnowledge maps to data manipulation
	// Combined should have both types

	totalConfidence := 0.0
	for _, mapping := range enriched {
		totalConfidence += mapping.Confidence
	}

	if totalConfidence == 0 {
		t.Error("Expected positive total confidence")
	}
}

func TestGetTechniqueDetails(t *testing.T) {
	mapper := NewMapper()

	mappings := map[string]Mapping{
		"T1078": {TechniqueID: "T1078", Confidence: 0.9},
		"T1190": {TechniqueID: "T1190", Confidence: 0.8},
	}

	details := mapper.GetTechniqueDetails(mappings)

	if len(details) == 0 {
		t.Fatal("Expected technique details")
	}

	// Verify details are populated
	for _, tech := range details {
		if tech.Name == "" {
			t.Error("Expected technique name to be populated")
		}
		if tech.Description == "" {
			t.Error("Expected technique description to be populated")
		}
	}
}

func TestGetTechniqueByID(t *testing.T) {
	tech := GetTechniqueByID("T1078")

	if tech == nil {
		t.Fatal("Expected to find technique T1078")
	}

	if tech.Name != "Valid Accounts" {
		t.Errorf("Expected 'Valid Accounts', got '%s'", tech.Name)
	}

	// Test non-existent technique
	nonExistent := GetTechniqueByID("T9999")
	if nonExistent != nil {
		t.Error("Expected nil for non-existent technique")
	}
}

func TestGetTechniquesByTactic(t *testing.T) {
	techniques := GetTechniquesByTactic(InitialAccess)

	if len(techniques) == 0 {
		t.Fatal("Expected techniques for Initial Access tactic")
	}

	// All returned techniques should have InitialAccess tactic
	for _, tech := range techniques {
		if tech.Tactic != InitialAccess {
			t.Errorf("Expected tactic %s, got %s", InitialAccess, tech.Tactic)
		}
	}
}

func TestAllTactics(t *testing.T) {
	tactics := AllTactics()

	if len(tactics) != 12 {
		t.Errorf("Expected 12 tactics, got %d", len(tactics))
	}

	// Verify all required tactics exist
	required := []Tactic{
		InitialAccess,
		Execution,
		Persistence,
		PrivilegeEscalation,
		DefenseEvasion,
		CredentialAccess,
		Discovery,
		LateralMovement,
		Collection,
		Exfiltration,
		CommandAndControl,
		Impact,
	}

	for _, tactic := range required {
		if _, ok := tactics[tactic]; !ok {
			t.Errorf("Missing required tactic: %s", tactic)
		}
	}
}

func TestAllTechniques(t *testing.T) {
	techniques := AllTechniques()

	if len(techniques) == 0 {
		t.Fatal("Expected techniques to be defined")
	}

	// Verify each technique has required fields
	for _, tech := range techniques {
		if tech.ID == "" {
			t.Error("Technique missing ID")
		}
		if tech.Name == "" {
			t.Error("Technique missing Name")
		}
		if tech.Description == "" {
			t.Error("Technique missing Description")
		}
		if tech.Tactic == "" {
			t.Error("Technique missing Tactic")
		}
	}
}
