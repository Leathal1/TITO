package collectors

import (
	"context"
	"testing"

	"github.com/Leathal1/TITO/pkg/models"
	"github.com/Leathal1/TITO/pkg/scanner"
)

func TestCodeAnalyzer_Collect(t *testing.T) {
	repo := &scanner.Repository{
		Language:  "go",
		Framework: "gin",
		Assets: []scanner.Asset{
			{
				ID:   "api-1",
				Type: scanner.AssetAPI,
				Name: "/api/users",
				Location: scanner.Location{
					File: "handlers/users.go",
					Line: 42,
				},
				Description: "HTTP endpoint: router.GET(\"/api/users\")",
				Exposed:     true,
			},
			{
				ID:   "db-1",
				Type: scanner.AssetDatabase,
				Name: "Database Query (SELECT)",
				Location: scanner.Location{
					File: "handlers/users.go",
					Line: 50,
				},
				Description: "SELECT * FROM users WHERE id = \" + userId",
				Sensitive:   true,
			},
			{
				ID:   "secret-1",
				Type: scanner.AssetSecret,
				Name: "Secret: api_key",
				Location: scanner.Location{
					File: "config/config.go",
					Line: 10,
				},
				Description: "api_key = \"sk-1234567890\"",
				Sensitive:   true,
			},
		},
		DataFlows: []scanner.DataFlow{
			{
				ID: "flow-1",
				Source: scanner.Location{
					File: "handlers/users.go",
					Line: 42,
				},
				Destination: scanner.Location{
					File: "handlers/users.go",
					Line: 50,
				},
				DataType:  "user_data",
				Sensitive: true,
			},
		},
	}

	analyzer := NewCodeAnalyzer(repo)
	ctx := context.Background()

	threats, err := analyzer.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect() failed: %v", err)
	}

	if len(threats) == 0 {
		t.Error("Expected threats to be detected, got none")
	}

	// Verify we got expected threat types
	foundUnauthAPI := false
	foundSQLInjection := false
	foundHardcodedSecret := false

	for _, threat := range threats {
		switch {
		case threat.Title == "Unauthenticated API Endpoint":
			foundUnauthAPI = true
			if threat.Severity != models.SeverityHigh {
				t.Errorf("Expected HIGH severity for unauth API, got %s", threat.Severity)
			}
		case threat.Title == "Potential SQL Injection":
			foundSQLInjection = true
			if threat.Severity != models.SeverityCritical {
				t.Errorf("Expected CRITICAL severity for SQL injection, got %s", threat.Severity)
			}
		case threat.Title == "Hardcoded Credential Detected":
			foundHardcodedSecret = true
			if threat.Severity != models.SeverityCritical {
				t.Errorf("Expected CRITICAL severity for hardcoded secret, got %s", threat.Severity)
			}
		}

		// Verify all threats have required fields
		if threat.ID == "" {
			t.Error("Threat missing ID")
		}
		if threat.Title == "" {
			t.Error("Threat missing title")
		}
		if threat.Description == "" {
			t.Error("Threat missing description")
		}
		if threat.StrideProfile == nil {
			t.Error("Threat missing STRIDE profile")
		}
		if len(threat.RecommendedActions) == 0 {
			t.Error("Threat missing recommended actions")
		}
		if len(threat.Indicators) == 0 {
			t.Error("Threat missing indicators")
		}
	}

	if !foundUnauthAPI {
		t.Error("Expected to find unauthenticated API threat")
	}
	if !foundSQLInjection {
		t.Error("Expected to find SQL injection threat")
	}
	if !foundHardcodedSecret {
		t.Error("Expected to find hardcoded secret threat")
	}
}

func TestCodeAnalyzer_AnalyzeAssets_UnauthAPI(t *testing.T) {
	repo := &scanner.Repository{
		Language:  "python",
		Framework: "flask",
		Assets: []scanner.Asset{
			{
				ID:          "api-test",
				Type:        scanner.AssetAPI,
				Name:        "/api/admin",
				Location:    scanner.Location{File: "app.py", Line: 100},
				Description: "@app.route('/api/admin')",
				Exposed:     true,
			},
		},
	}

	analyzer := NewCodeAnalyzer(repo)
	threats := analyzer.analyzeAssets(context.Background())

	if len(threats) == 0 {
		t.Fatal("Expected unauthenticated API threat")
	}

	threat := threats[0]
	if threat.Title != "Unauthenticated API Endpoint" {
		t.Errorf("Expected 'Unauthenticated API Endpoint', got '%s'", threat.Title)
	}
	if threat.Severity != models.SeverityHigh {
		t.Errorf("Expected HIGH severity, got %s", threat.Severity)
	}
}

func TestCodeAnalyzer_AnalyzeAssets_SQLInjection(t *testing.T) {
	repo := &scanner.Repository{
		Assets: []scanner.Asset{
			{
				ID:          "db-concat",
				Type:        scanner.AssetDatabase,
				Name:        "Database Query",
				Location:    scanner.Location{File: "db.go", Line: 50},
				Description: "db.Query(\"SELECT * FROM users WHERE name = \" + userName)",
			},
		},
	}

	analyzer := NewCodeAnalyzer(repo)
	threats := analyzer.analyzeAssets(context.Background())

	if len(threats) == 0 {
		t.Fatal("Expected SQL injection threat")
	}

	threat := threats[0]
	if threat.Title != "Potential SQL Injection" {
		t.Errorf("Expected 'Potential SQL Injection', got '%s'", threat.Title)
	}
	if threat.Severity != models.SeverityCritical {
		t.Errorf("Expected CRITICAL severity, got %s", threat.Severity)
	}
}

func TestCodeAnalyzer_AnalyzeAssets_HardcodedSecret(t *testing.T) {
	repo := &scanner.Repository{
		Assets: []scanner.Asset{
			{
				ID:          "secret-hardcoded",
				Type:        scanner.AssetSecret,
				Name:        "Secret: password",
				Location:    scanner.Location{File: "config.go", Line: 10},
				Description: "password = \"mysecretpass123\"",
				Sensitive:   true,
			},
		},
	}

	analyzer := NewCodeAnalyzer(repo)
	threats := analyzer.analyzeAssets(context.Background())

	if len(threats) == 0 {
		t.Fatal("Expected hardcoded secret threat")
	}

	threat := threats[0]
	if threat.Title != "Hardcoded Credential Detected" {
		t.Errorf("Expected 'Hardcoded Credential Detected', got '%s'", threat.Title)
	}
	if threat.Severity != models.SeverityCritical {
		t.Errorf("Expected CRITICAL severity, got %s", threat.Severity)
	}
}

func TestCodeAnalyzer_AnalyzeAssets_IgnoreEnvFiles(t *testing.T) {
	repo := &scanner.Repository{
		Assets: []scanner.Asset{
			{
				ID:          "env-var",
				Type:        scanner.AssetSecret,
				Name:        "ENV: API_KEY",
				Location:    scanner.Location{File: ".env", Line: 5},
				Description: "API_KEY=xyz",
				Sensitive:   true,
			},
		},
	}

	analyzer := NewCodeAnalyzer(repo)
	threats := analyzer.analyzeAssets(context.Background())

	// .env files should NOT trigger hardcoded secret warnings
	for _, threat := range threats {
		if threat.Title == "Hardcoded Credential Detected" {
			t.Error("Should not flag .env file secrets as hardcoded")
		}
	}
}

func TestCodeAnalyzer_AnalyzeDataFlows_SensitiveExternalFlow(t *testing.T) {
	repo := &scanner.Repository{
		Assets: []scanner.Asset{
			{
				ID:          "api-1",
				Type:        scanner.AssetAPI,
				Location:    scanner.Location{File: "handler.go", Line: 10},
			},
			{
				ID:          "ext-1",
				Type:        scanner.AssetNetwork,
				Location:    scanner.Location{File: "handler.go", Line: 20},
			},
		},
		DataFlows: []scanner.DataFlow{
			{
				ID:          "flow-1",
				Source:      scanner.Location{File: "handler.go", Line: 10},
				Destination: scanner.Location{File: "handler.go", Line: 20},
				DataType:    "user_data",
				Sensitive:   true,
			},
		},
	}

	analyzer := NewCodeAnalyzer(repo)
	threats := analyzer.analyzeDataFlows(context.Background())

	if len(threats) == 0 {
		t.Fatal("Expected sensitive data exposure threat")
	}

	threat := threats[0]
	if threat.Title != "Sensitive Data Exposure" {
		t.Errorf("Expected 'Sensitive Data Exposure', got '%s'", threat.Title)
	}
	if threat.Severity != models.SeverityHigh {
		t.Errorf("Expected HIGH severity, got %s", threat.Severity)
	}
}

func TestCodeAnalyzer_AnalyzeMAESTRO_LLMFramework(t *testing.T) {
	repo := &scanner.Repository{
		Assets: []scanner.Asset{
			{
				ID:          "llm-1",
				Type:        scanner.AssetNetwork,
				Name:        "OpenAI API Call",
				Location:    scanner.Location{File: "ai/agent.go", Line: 15},
				Description: "openai.ChatCompletion",
			},
		},
	}

	analyzer := NewCodeAnalyzer(repo)
	threats := analyzer.analyzeMAESTROPatterns(context.Background())

	if len(threats) == 0 {
		t.Fatal("Expected LLM prompt injection threat")
	}

	threat := threats[0]
	if threat.Title != "LLM Integration - Prompt Injection Risk" {
		t.Errorf("Expected 'LLM Integration - Prompt Injection Risk', got '%s'", threat.Title)
	}
	if threat.Severity != models.SeverityHigh {
		t.Errorf("Expected HIGH severity, got %s", threat.Severity)
	}

	// Check MAESTRO tag
	foundMAESTROTag := false
	for _, tag := range threat.Tags {
		if tag == "MAESTRO" {
			foundMAESTROTag = true
			break
		}
	}
	if !foundMAESTROTag {
		t.Error("Expected MAESTRO tag on LLM threat")
	}
}

func TestCodeAnalyzer_AnalyzeMAESTRO_ToolLoading(t *testing.T) {
	repo := &scanner.Repository{
		Assets: []scanner.Asset{
			{
				ID:          "tool-1",
				Type:        scanner.AssetAPI,
				Name:        "Tool Registry",
				Location:    scanner.Location{File: "tools/registry.go", Line: 30},
				Description: "function_calling tools",
			},
		},
	}

	analyzer := NewCodeAnalyzer(repo)
	threats := analyzer.analyzeMAESTROPatterns(context.Background())

	if len(threats) == 0 {
		t.Fatal("Expected tool poisoning threat")
	}

	threat := threats[0]
	if threat.Title != "Dynamic Tool Loading - Tool Poisoning Risk" {
		t.Errorf("Expected 'Dynamic Tool Loading - Tool Poisoning Risk', got '%s'", threat.Title)
	}
}

func TestCodeAnalyzer_AnalyzeMAESTRO_InterServiceComm(t *testing.T) {
	repo := &scanner.Repository{
		Assets: []scanner.Asset{
			{
				ID:          "grpc-1",
				Type:        scanner.AssetNetwork,
				Name:        "gRPC Service",
				Location:    scanner.Location{File: "services/grpc.go", Line: 40},
				Description: "grpc server",
			},
		},
	}

	analyzer := NewCodeAnalyzer(repo)
	threats := analyzer.analyzeMAESTROPatterns(context.Background())

	if len(threats) == 0 {
		t.Fatal("Expected inter-agent communication threat")
	}

	threat := threats[0]
	if threat.Title != "Inter-Agent Communication - Authentication Risk" {
		t.Errorf("Expected 'Inter-Agent Communication - Authentication Risk', got '%s'", threat.Title)
	}
	if threat.Severity != models.SeverityMedium {
		t.Errorf("Expected MEDIUM severity, got %s", threat.Severity)
	}
}

func TestCodeAnalyzer_Name(t *testing.T) {
	analyzer := NewCodeAnalyzer(nil)
	if analyzer.Name() != "CodeAnalyzer" {
		t.Errorf("Expected name 'CodeAnalyzer', got '%s'", analyzer.Name())
	}
}

func TestCodeAnalyzer_Status(t *testing.T) {
	analyzer := NewCodeAnalyzer(nil)
	status := analyzer.Status()

	if status.Name != "CodeAnalyzer" {
		t.Errorf("Expected status name 'CodeAnalyzer', got '%s'", status.Name)
	}
}

func TestCodeAnalyzer_NilRepository(t *testing.T) {
	analyzer := NewCodeAnalyzer(nil)
	ctx := context.Background()

	_, err := analyzer.Collect(ctx)
	if err == nil {
		t.Error("Expected error when repository is nil")
	}
}

func TestCodeAnalyzer_ThreatHasSTRIDEProfile(t *testing.T) {
	repo := &scanner.Repository{
		Assets: []scanner.Asset{
			{
				ID:          "api-1",
				Type:        scanner.AssetAPI,
				Name:        "/test",
				Location:    scanner.Location{File: "test.go", Line: 1},
				Exposed:     true,
			},
		},
	}

	analyzer := NewCodeAnalyzer(repo)
	threats := analyzer.analyzeAssets(context.Background())

	if len(threats) == 0 {
		t.Fatal("Expected at least one threat")
	}

	for _, threat := range threats {
		if threat.StrideProfile == nil {
			t.Error("Threat missing STRIDE profile")
			continue
		}

		if threat.StrideProfile.PrimaryCategory == "" {
			t.Error("STRIDE profile missing primary category")
		}

		if len(threat.StrideProfile.ConfidenceScores) == 0 {
			t.Error("STRIDE profile missing confidence scores")
		}
	}
}

func TestCodeAnalyzer_ThreatHasRecommendations(t *testing.T) {
	repo := &scanner.Repository{
		Assets: []scanner.Asset{
			{
				ID:          "db-1",
				Type:        scanner.AssetDatabase,
				Location:    scanner.Location{File: "db.go", Line: 10},
				Description: "SELECT + concat user input",
			},
		},
	}

	analyzer := NewCodeAnalyzer(repo)
	threats := analyzer.analyzeAssets(context.Background())

	if len(threats) == 0 {
		t.Fatal("Expected at least one threat")
	}

	for _, threat := range threats {
		if len(threat.RecommendedActions) == 0 {
			t.Errorf("Threat '%s' has no recommended actions", threat.Title)
		}

		// Verify recommendations are actionable (not empty strings)
		for i, action := range threat.RecommendedActions {
			if action == "" {
				t.Errorf("Threat '%s' has empty recommendation at index %d", threat.Title, i)
			}
		}
	}
}

func TestCodeAnalyzer_PriorityScoreCalculated(t *testing.T) {
	repo := &scanner.Repository{
		Assets: []scanner.Asset{
			{
				ID:       "critical-1",
				Type:     scanner.AssetSecret,
				Location: scanner.Location{File: "main.go", Line: 1},
			},
		},
	}

	analyzer := NewCodeAnalyzer(repo)
	threats, _ := analyzer.Collect(context.Background())

	if len(threats) == 0 {
		t.Fatal("Expected at least one threat")
	}

	for _, threat := range threats {
		if threat.PriorityScore == 0.0 {
			t.Errorf("Threat '%s' has zero priority score", threat.Title)
		}
		if threat.PriorityScore < 0.0 || threat.PriorityScore > 1.0 {
			t.Errorf("Threat '%s' has invalid priority score: %f", threat.Title, threat.PriorityScore)
		}
	}
}
