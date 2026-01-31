package maestro

import (
	"os"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	os.Setenv("TITO_SKIP_LICENSE", "1")
	os.Exit(m.Run())
}

func TestNewClassifier(t *testing.T) {
	classifier := NewClassifier()
	if classifier == nil {
		t.Fatal("NewClassifier returned nil")
	}

	if len(classifier.layers) != 7 {
		t.Errorf("Expected 7 layers, got %d", len(classifier.layers))
	}

	if len(classifier.patterns) != 7 {
		t.Errorf("Expected 7 pattern sets, got %d", len(classifier.patterns))
	}
}

func TestClassify_PromptInjection(t *testing.T) {
	classifier := NewClassifier()

	input := ClassificationInput{
		SystemDescription: "AI assistant with prompt injection vulnerability allowing jailbreak attacks",
		Technologies:      []string{"GPT-4", "OpenAI"},
		HasAgents:         true,
		CWEIDs:            []int{77, 94},
	}

	profile := classifier.Classify(input)

	if profile.PrimaryLayer != FoundationModels {
		t.Errorf("Expected primary layer %s, got %s", FoundationModels, profile.PrimaryLayer)
	}

	if profile.ConfidenceScores[FoundationModels] < 0.5 {
		t.Errorf("Expected high confidence for Foundation Models, got %.2f",
			profile.ConfidenceScores[FoundationModels])
	}

	if len(profile.IdentifiedThreats) == 0 {
		t.Error("Expected identified threats, got none")
	}

	// Check that "Prompt Injection" is in identified threats
	found := false
	for _, threat := range profile.IdentifiedThreats {
		if strings.Contains(threat, "Prompt Injection") {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected 'Prompt Injection' in identified threats")
	}
}

func TestClassify_RAGPoisoning(t *testing.T) {
	classifier := NewClassifier()

	input := ClassificationInput{
		SystemDescription: "RAG system with vector database vulnerable to knowledge base poisoning attacks",
		Technologies:      []string{"ChromaDB", "LangChain", "OpenAI Embeddings"},
		HasRAG:            true,
		HasAgents:         true,
	}

	profile := classifier.Classify(input)

	// Should detect Data & Knowledge layer due to RAG keywords
	score := profile.ConfidenceScores[DataKnowledge]
	if score < 0.3 {
		t.Errorf("Expected moderate to high confidence for Data & Knowledge layer, got %.2f", score)
	}

	// Either DataKnowledge or AgentFrameworks should be primary or secondary
	layerPresent := false
	if profile.PrimaryLayer == DataKnowledge || profile.PrimaryLayer == AgentFrameworks {
		layerPresent = true
	}
	for _, layer := range profile.SecondaryLayers {
		if layer == DataKnowledge || layer == AgentFrameworks {
			layerPresent = true
		}
	}

	if !layerPresent {
		t.Error("Expected Data & Knowledge or Agent Frameworks layer in classification")
	}
}

func TestClassify_MultiAgentSystem(t *testing.T) {
	classifier := NewClassifier()

	input := ClassificationInput{
		SystemDescription: "Multi-agent system with inter-agent communication and message spoofing risks",
		Technologies:      []string{"AutoGen", "CrewAI"},
		HasAgents:         true,
		HasMultiAgent:     true,
	}

	profile := classifier.Classify(input)

	// Should have high score for Agent Communication layer
	score := profile.ConfidenceScores[AgentCommunication]
	if score < 0.4 {
		t.Errorf("Expected high confidence for Agent Communication, got %.2f", score)
	}

	// AgentCommunication or AgentFrameworks should be in classification
	layerPresent := false
	if profile.PrimaryLayer == AgentCommunication || profile.PrimaryLayer == AgentFrameworks {
		layerPresent = true
	}
	for _, layer := range profile.SecondaryLayers {
		if layer == AgentCommunication || layer == AgentFrameworks {
			layerPresent = true
		}
	}

	if !layerPresent {
		t.Error("Expected Agent Communication or Agent Frameworks in classification")
	}
}

func TestClassify_MCPServerExploit(t *testing.T) {
	classifier := NewClassifier()

	input := ClassificationInput{
		SystemDescription: "AI agent using MCP server with tool poisoning and API key theft vulnerabilities",
		Technologies:      []string{"MCP", "Anthropic", "Claude"},
		HasToolCalling:    true,
		CWEIDs:            []int{798, 522},
	}

	profile := classifier.Classify(input)

	// Should detect Tooling & Integration layer
	score := profile.ConfidenceScores[ToolingIntegration]
	if score < 0.3 {
		t.Errorf("Expected moderate to high confidence for Tooling & Integration, got %.2f", score)
	}
}

func TestClassify_ContainerEscape(t *testing.T) {
	classifier := NewClassifier()

	input := ClassificationInput{
		SystemDescription: "Containerized model serving with sandbox escape and resource exhaustion risks",
		Technologies:      []string{"Docker", "Kubernetes", "vLLM"},
		DeploymentModel:   "cloud",
		CWEIDs:            []int{400, 770},
	}

	profile := classifier.Classify(input)

	// Should detect Deployment & Infrastructure layer
	score := profile.ConfidenceScores[DeploymentInfra]
	if score < 0.3 {
		t.Errorf("Expected moderate to high confidence for Deployment & Infrastructure, got %.2f", score)
	}
}

func TestClassify_ComplianceGaps(t *testing.T) {
	classifier := NewClassifier()

	input := ClassificationInput{
		SystemDescription: "AI system with GDPR compliance gaps and audit trail manipulation risks",
		Technologies:      []string{"GPT-4"},
		Context: map[string]interface{}{
			"compliance_required": true,
		},
	}

	profile := classifier.Classify(input)

	// Should have some score for Ecosystem & Governance
	score := profile.ConfidenceScores[EcosystemGovernance]
	if score < 0.1 {
		t.Errorf("Expected some confidence for Ecosystem & Governance, got %.2f", score)
	}
}

func TestClassify_EmptyInput(t *testing.T) {
	classifier := NewClassifier()

	input := ClassificationInput{
		SystemDescription: "Generic system",
	}

	profile := classifier.Classify(input)

	// Should still classify to some layer (default to Foundation Models)
	if profile.PrimaryLayer == "" {
		t.Error("Expected primary layer even for empty input")
	}

	// Should have some confidence scores
	if len(profile.ConfidenceScores) == 0 {
		t.Error("Expected confidence scores even for empty input")
	}
}

func TestProfileString(t *testing.T) {
	profile := &Profile{
		PrimaryLayer:    FoundationModels,
		SecondaryLayers: []Layer{DataKnowledge, AgentFrameworks},
		ConfidenceScores: map[Layer]float64{
			FoundationModels: 0.9,
			DataKnowledge:    0.6,
			AgentFrameworks:  0.5,
		},
	}

	result := profile.String()

	if !strings.Contains(result, string(FoundationModels)) {
		t.Error("Expected primary layer in string representation")
	}

	if !strings.Contains(result, string(DataKnowledge)) {
		t.Error("Expected secondary layers in string representation")
	}
}

func TestExplainClassification(t *testing.T) {
	classifier := NewClassifier()

	input := ClassificationInput{
		SystemDescription: "AI agent with prompt injection vulnerability",
		Technologies:      []string{"GPT-4"},
		HasAgents:         true,
	}

	profile := classifier.Classify(input)
	explanation := classifier.ExplainClassification(profile)

	if !strings.Contains(explanation, "MAESTRO Classification") {
		t.Error("Expected MAESTRO Classification header in explanation")
	}

	if !strings.Contains(explanation, "Primary Layer") {
		t.Error("Expected Primary Layer section in explanation")
	}

	if !strings.Contains(explanation, "Detection Strategies") {
		t.Error("Expected Detection Strategies in explanation")
	}

	if !strings.Contains(explanation, "Mitigation Strategies") {
		t.Error("Expected Mitigation Strategies in explanation")
	}
}

func TestGetLayerInfo(t *testing.T) {
	info := GetLayerInfo(FoundationModels)

	if info.FullName == "" {
		t.Error("Expected layer info, got empty")
	}

	if len(info.Threats) == 0 {
		t.Error("Expected threats in layer info")
	}

	if len(info.Keywords) == 0 {
		t.Error("Expected keywords in layer info")
	}

	// Test invalid layer
	invalidInfo := GetLayerInfo("invalid")
	if invalidInfo.FullName != "" {
		t.Error("Expected empty info for invalid layer")
	}
}

func TestAllLayers(t *testing.T) {
	layers := AllLayers()

	if len(layers) != 7 {
		t.Errorf("Expected 7 layers, got %d", len(layers))
	}

	// Verify all layers are present
	expectedLayers := []Layer{
		FoundationModels,
		DataKnowledge,
		AgentFrameworks,
		ToolingIntegration,
		AgentCommunication,
		DeploymentInfra,
		EcosystemGovernance,
	}

	for _, expected := range expectedLayers {
		if _, ok := layers[expected]; !ok {
			t.Errorf("Expected layer %s not found", expected)
		}
	}

	// Verify each layer has required fields
	for layer, info := range layers {
		if info.FullName == "" {
			t.Errorf("Layer %s missing FullName", layer)
		}
		if info.Question == "" {
			t.Errorf("Layer %s missing Question", layer)
		}
		if len(info.Threats) == 0 {
			t.Errorf("Layer %s missing Threats", layer)
		}
		if len(info.Keywords) == 0 {
			t.Errorf("Layer %s missing Keywords", layer)
		}
	}
}

func TestFormatFloat(t *testing.T) {
	tests := []struct {
		input    float64
		decimals int
		expected string
	}{
		{0.123, 2, "0.11"}, // Rounding
		{0.999, 2, "1.00"},
		{1.0, 2, "1.00"},
		{0.5, 1, "0.5"},
	}

	for _, test := range tests {
		result := formatFloat(test.input, test.decimals)
		if result != test.expected {
			t.Errorf("formatFloat(%.3f, %d) = %s, want %s",
				test.input, test.decimals, result, test.expected)
		}
	}
}
