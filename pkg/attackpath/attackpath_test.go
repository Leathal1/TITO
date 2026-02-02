package attackpath

import (
	"testing"

	"github.com/Leathal1/TITO/v2/pkg/dataflow"
)

// Helper function to create test diagram data
func createTestDiagram() *dataflow.DiagramData {
	return &dataflow.DiagramData{
		Nodes: []dataflow.Node{
			{
				ID:        "api-gateway",
				Label:     "API Gateway",
				Type:      dataflow.NodeAPI,
				RiskLevel: dataflow.RiskHigh,
				Findings: []dataflow.Finding{
					{
						ID:       "f1",
						Severity: "high",
						STRIDE:   "Tampering",
						Title:    "SQL Injection",
					},
				},
			},
			{
				ID:        "backend",
				Label:     "Backend Service",
				Type:      dataflow.NodeService,
				RiskLevel: dataflow.RiskMedium,
			},
			{
				ID:        "database",
				Label:     "Users Database",
				Type:      dataflow.NodeDatabase,
				RiskLevel: dataflow.RiskCritical,
			},
		},
		Edges: []dataflow.Edge{
			{
				ID:        "e1",
				Source:    "api-gateway",
				Target:    "backend",
				Sensitive: true,
				Encrypted: false,
				Protocols: []string{"HTTP"},
			},
			{
				ID:        "e2",
				Source:    "backend",
				Target:    "database",
				Sensitive: true,
				Encrypted: false,
				Protocols: []string{"SQL"},
			},
		},
		TrustBoundaries: []dataflow.TrustBoundary{
			{
				ID:    "tb1",
				Name:  "Internet",
				Nodes: []string{"api-gateway"},
				Zone:  "internet",
			},
			{
				ID:    "tb2",
				Name:  "Internal",
				Nodes: []string{"backend", "database"},
				Zone:  "internal",
			},
		},
	}
}

// Test graph building
func TestGraphBuilder_Build(t *testing.T) {
	diagram := createTestDiagram()
	builder := NewGraphBuilder(diagram)
	graph := builder.Build()

	// Check nodes
	if len(graph.Nodes) != 3 {
		t.Errorf("Expected 3 nodes, got %d", len(graph.Nodes))
	}

	// Check entry points
	if len(graph.EntryPoints) == 0 {
		t.Error("Expected at least one entry point")
	}

	// API Gateway should be an entry point
	foundEntry := false
	for _, ep := range graph.EntryPoints {
		if ep == "api-gateway" {
			foundEntry = true
			break
		}
	}
	if !foundEntry {
		t.Error("API Gateway should be identified as entry point")
	}

	// Check crown jewels
	if len(graph.CrownJewels) == 0 {
		t.Error("Expected at least one crown jewel")
	}

	// Database should be a crown jewel
	foundCrown := false
	for _, cj := range graph.CrownJewels {
		if cj == "database" {
			foundCrown = true
			break
		}
	}
	if !foundCrown {
		t.Error("Database should be identified as crown jewel")
	}

	// Check edges
	if len(graph.Edges) != 2 {
		t.Errorf("Expected 2 edges, got %d", len(graph.Edges))
	}
}

// Test exploitability calculation
func TestGraphBuilder_CalculateExploitability(t *testing.T) {
	builder := NewGraphBuilder(createTestDiagram())

	tests := []struct {
		name     string
		findings []dataflow.Finding
		expected float64
	}{
		{
			name:     "No findings",
			findings: []dataflow.Finding{},
			expected: 0.1,
		},
		{
			name: "Critical finding",
			findings: []dataflow.Finding{
				{Severity: "critical"},
			},
			expected: 0.36, // 0.4 / (1.0 + 0.1)
		},
		{
			name: "Multiple findings",
			findings: []dataflow.Finding{
				{Severity: "high"},
				{Severity: "medium"},
			},
			expected: 0.42, // (0.3 + 0.2) / (1.0 + 0.2)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := builder.calculateExploitability(tt.findings)
			if result < tt.expected-0.01 || result > tt.expected+0.01 {
				t.Errorf("Expected exploitability ~%.2f, got %.2f", tt.expected, result)
			}
		})
	}
}

// Test path finding
func TestPathFinder_FindAllPaths(t *testing.T) {
	diagram := createTestDiagram()
	builder := NewGraphBuilder(diagram)
	graph := builder.Build()

	finder := NewPathFinder(graph)
	paths := finder.FindAllPaths(5)

	if len(paths) == 0 {
		t.Error("Expected to find at least one path")
	}

	// Check that paths go from entry to crown jewel
	for _, path := range paths {
		if path.EntryPoint == "" {
			t.Error("Path should have an entry point")
		}
		if path.Target == "" {
			t.Error("Path should have a target")
		}
		if len(path.Steps) == 0 {
			t.Error("Path should have steps")
		}
	}
}

// Test shortest path finding
func TestPathFinder_FindShortestPaths(t *testing.T) {
	diagram := createTestDiagram()
	builder := NewGraphBuilder(diagram)
	graph := builder.Build()

	finder := NewPathFinder(graph)
	paths := finder.FindShortestPaths()

	if len(paths) == 0 {
		t.Error("Expected to find at least one shortest path")
	}

	// Shortest path should be direct: api-gateway -> backend -> database
	for _, path := range paths {
		if path.EntryPoint == "api-gateway" && path.Target == "database" {
			if len(path.Steps) != 2 {
				t.Errorf("Expected 2 steps for direct path, got %d", len(path.Steps))
			}
		}
	}
}

// Test critical paths
func TestPathFinder_FindCriticalPaths(t *testing.T) {
	diagram := createTestDiagram()
	builder := NewGraphBuilder(diagram)
	graph := builder.Build()

	finder := NewPathFinder(graph)
	paths := finder.FindCriticalPaths(5)

	if len(paths) == 0 {
		t.Error("Expected to find critical paths")
	}

	// Paths should be scored
	for _, path := range paths {
		if path.CompositeRisk == 0 {
			t.Error("Critical path should have non-zero risk score")
		}
	}

	// Paths should be sorted by risk (descending)
	for i := 1; i < len(paths); i++ {
		if paths[i].CompositeRisk > paths[i-1].CompositeRisk {
			t.Error("Paths should be sorted by descending risk")
		}
	}
}

// Test scoring
func TestScorer_ScorePath(t *testing.T) {
	diagram := createTestDiagram()
	builder := NewGraphBuilder(diagram)
	graph := builder.Build()

	scorer := NewScorer(graph)

	// Create a simple path
	steps := []AttackStep{
		{
			FromNode:   "api-gateway",
			ToNode:     "backend",
			Difficulty: 0.3,
			Technique:  "API Exploitation",
		},
		{
			FromNode:   "backend",
			ToNode:     "database",
			Difficulty: 0.2,
			Technique:  "Database Access",
		},
	}

	score := scorer.ScorePath(steps)

	if score <= 0 || score > 10 {
		t.Errorf("Expected score between 0 and 10, got %.2f", score)
	}

	// Higher difficulty should result in lower score (harder for attacker)
	hardSteps := []AttackStep{
		{
			FromNode:   "api-gateway",
			ToNode:     "backend",
			Difficulty: 0.9,
			Technique:  "API Exploitation",
		},
		{
			FromNode:   "backend",
			ToNode:     "database",
			Difficulty: 0.8,
			Technique:  "Database Access",
		},
	}

	hardScore := scorer.ScorePath(hardSteps)

	if hardScore >= score {
		t.Error("Harder path should have lower risk score")
	}
}

// Test narrative generation
func TestNarrativeGenerator_GenerateNarrative(t *testing.T) {
	diagram := createTestDiagram()
	builder := NewGraphBuilder(diagram)
	graph := builder.Build()

	generator := NewNarrativeGenerator(graph)

	path := AttackPath{
		ID:              "test-path",
		EntryPoint:      "api-gateway",
		Target:          "database",
		CompositeRisk:   8.5,
		TotalDifficulty: 0.25,
		Steps: []AttackStep{
			{
				FromNode:   "api-gateway",
				ToNode:     "backend",
				Technique:  "API Exploitation",
				Difficulty: 0.3,
				MitreID:    "T1190",
			},
			{
				FromNode:   "backend",
				ToNode:     "database",
				Technique:  "Database Access",
				Difficulty: 0.2,
			},
		},
	}

	narrative := generator.GenerateNarrative(path)

	if narrative == "" {
		t.Error("Expected non-empty narrative")
	}

	// Check for key elements
	if !contains(narrative, "API Gateway") {
		t.Error("Narrative should mention entry point")
	}
	if !contains(narrative, "Database") {
		t.Error("Narrative should mention target")
	}
	if !contains(narrative, "CROWN JEWEL") {
		t.Error("Narrative should identify crown jewel")
	}
}

// Test diamond topology (multiple paths)
func TestPathFinder_DiamondTopology(t *testing.T) {
	diagram := &dataflow.DiagramData{
		Nodes: []dataflow.Node{
			{ID: "entry", Label: "Entry", Type: dataflow.NodeAPI, RiskLevel: dataflow.RiskLow},
			{ID: "path1", Label: "Path1", Type: dataflow.NodeService, RiskLevel: dataflow.RiskMedium},
			{ID: "path2", Label: "Path2", Type: dataflow.NodeService, RiskLevel: dataflow.RiskMedium},
			{ID: "target", Label: "Target", Type: dataflow.NodeDatabase, RiskLevel: dataflow.RiskCritical},
		},
		Edges: []dataflow.Edge{
			{ID: "e1", Source: "entry", Target: "path1"},
			{ID: "e2", Source: "entry", Target: "path2"},
			{ID: "e3", Source: "path1", Target: "target"},
			{ID: "e4", Source: "path2", Target: "target"},
		},
		TrustBoundaries: []dataflow.TrustBoundary{
			{ID: "tb1", Nodes: []string{"entry"}, Zone: "internet"},
			{ID: "tb2", Nodes: []string{"path1", "path2", "target"}, Zone: "internal"},
		},
	}

	builder := NewGraphBuilder(diagram)
	graph := builder.Build()

	finder := NewPathFinder(graph)
	paths := finder.FindAllPaths(5)

	// Should find 2 paths (entry -> path1 -> target, entry -> path2 -> target)
	if len(paths) < 2 {
		t.Errorf("Expected at least 2 paths in diamond topology, got %d", len(paths))
	}
}

// Test cycle detection
func TestPathFinder_CycleDetection(t *testing.T) {
	diagram := &dataflow.DiagramData{
		Nodes: []dataflow.Node{
			{ID: "entry", Label: "Entry", Type: dataflow.NodeAPI},
			{ID: "node1", Label: "Node1", Type: dataflow.NodeService},
			{ID: "node2", Label: "Node2", Type: dataflow.NodeService},
			{ID: "target", Label: "Target", Type: dataflow.NodeDatabase},
		},
		Edges: []dataflow.Edge{
			{ID: "e1", Source: "entry", Target: "node1"},
			{ID: "e2", Source: "node1", Target: "node2"},
			{ID: "e3", Source: "node2", Target: "node1"}, // Cycle
			{ID: "e4", Source: "node2", Target: "target"},
		},
		TrustBoundaries: []dataflow.TrustBoundary{
			{ID: "tb1", Nodes: []string{"entry"}, Zone: "internet"},
			{ID: "tb2", Nodes: []string{"node1", "node2", "target"}, Zone: "internal"},
		},
	}

	builder := NewGraphBuilder(diagram)
	graph := builder.Build()

	finder := NewPathFinder(graph)
	paths := finder.FindAllPaths(10)

	// Should still find paths without infinite loops
	if len(paths) == 0 {
		t.Error("Should find paths even with cycles")
	}

	// Check that at least one valid path exists (entry -> ... -> target)
	foundValidPath := false
	for _, path := range paths {
		if path.EntryPoint == "entry" && path.Target == "target" {
			// This path should be valid
			if len(path.Steps) > 0 && len(path.Steps) < 10 {
				foundValidPath = true
				break
			}
		}
	}
	
	if !foundValidPath {
		t.Error("Should find at least one valid path from entry to target")
	}
}

// Test risk level categorization
func TestGetRiskLevel(t *testing.T) {
	tests := []struct {
		score    float64
		expected string
	}{
		{9.5, "CRITICAL"},
		{8.0, "CRITICAL"},
		{7.5, "HIGH"},
		{6.0, "HIGH"},
		{5.0, "MEDIUM"},
		{4.0, "MEDIUM"},
		{2.0, "LOW"},
	}

	for _, tt := range tests {
		result := GetRiskLevel(tt.score)
		if result != tt.expected {
			t.Errorf("Score %.1f: expected %s, got %s", tt.score, tt.expected, result)
		}
	}
}

// Test MITRE tactics extraction
func TestExtractMitreTactics(t *testing.T) {
	steps := []AttackStep{
		{MitreID: "T1190", Technique: "Initial Access"},
		{MitreID: "T1021", Technique: "Lateral Movement"},
		{MitreID: "T1212", Technique: "Credential Access"},
	}

	tactics := ExtractMitreTactics(steps)

	if len(tactics) == 0 {
		t.Error("Expected to extract tactics")
	}

	// Should have Initial Access
	foundInitialAccess := false
	for _, tactic := range tactics {
		if tactic == "Initial Access" {
			foundInitialAccess = true
			break
		}
	}
	if !foundInitialAccess {
		t.Error("Should include Initial Access tactic")
	}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || len(s) >= len(substr) && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
