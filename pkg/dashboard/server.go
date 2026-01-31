package dashboard

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"sync"

	"github.com/Leathal1/TITO/pkg/mapper"
	"github.com/Leathal1/TITO/pkg/models"
	"github.com/Leathal1/TITO/pkg/scanner"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

// Server serves the threat intelligence dashboard
type Server struct {
	addr           string
	repositories   map[string]*scanner.Repository
	mappedThreats  map[string][]mapper.MappedThreat
	mu             sync.RWMutex
	templates      *template.Template
}

// NewServer creates a new dashboard server
func NewServer(addr string) (*Server, error) {
	templates, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse templates: %w", err)
	}

	return &Server{
		addr:          addr,
		repositories:  make(map[string]*scanner.Repository),
		mappedThreats: make(map[string][]mapper.MappedThreat),
		templates:     templates,
	}, nil
}

// AddRepository adds a scanned repository to the dashboard
func (s *Server) AddRepository(repo *scanner.Repository, threats []mapper.MappedThreat) {
	s.mu.Lock()
	defer s.mu.Unlock()

	repoID := extractRepoID(repo.URL)
	s.repositories[repoID] = repo
	s.mappedThreats[repoID] = threats
}

// Start starts the HTTP server
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// Static files
	mux.Handle("/static/", http.FileServer(http.FS(staticFS)))

	// Pages
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/repository/", s.handleRepository)

	// API endpoints
	mux.HandleFunc("/api/repositories", s.handleAPIRepositories)
	mux.HandleFunc("/api/repository/", s.handleAPIRepository)
	mux.HandleFunc("/api/threats/", s.handleAPIThreats)
	mux.HandleFunc("/api/assets/", s.handleAPIAssets)
	mux.HandleFunc("/api/flows/", s.handleAPIFlows)
	mux.HandleFunc("/api/mitigations/", s.handleAPIMitigations)

	server := &http.Server{
		Addr:    s.addr,
		Handler: mux,
	}

	log.Printf("🚀 TITO Dashboard starting on http://%s", s.addr)
	log.Printf("📊 View dashboard: http://%s", s.addr)

	// Start server
	go func() {
		<-ctx.Done()
		server.Shutdown(context.Background())
	}()

	return server.ListenAndServe()
}

// Handlers

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data := struct {
		Repositories []RepositorySummary
		TotalThreats int
		TotalAssets  int
	}{
		Repositories: make([]RepositorySummary, 0),
	}

	for id, repo := range s.repositories {
		threats := s.mappedThreats[id]
		summary := RepositorySummary{
			ID:           id,
			URL:          repo.URL,
			Language:     repo.Language,
			Framework:    repo.Framework,
			ThreatCount:  len(threats),
			AssetCount:   len(repo.Assets),
			CriticalCount: countBySeverity(threats, models.SeverityCritical),
		}
		data.Repositories = append(data.Repositories, summary)
		data.TotalThreats += len(threats)
		data.TotalAssets += len(repo.Assets)
	}

	s.templates.ExecuteTemplate(w, "index.html", data)
}

func (s *Server) handleRepository(w http.ResponseWriter, r *http.Request) {
	repoID := r.URL.Path[len("/repository/"):]

	s.mu.RLock()
	repo, exists := s.repositories[repoID]
	threats := s.mappedThreats[repoID]
	s.mu.RUnlock()

	if !exists {
		http.NotFound(w, r)
		return
	}

	data := struct {
		Repository *scanner.Repository
		Threats    []mapper.MappedThreat
		Stats      RepositoryStats
	}{
		Repository: repo,
		Threats:    threats,
		Stats:      calculateStats(repo, threats),
	}

	s.templates.ExecuteTemplate(w, "repository.html", data)
}

// API Handlers

func (s *Server) handleAPIRepositories(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	repos := make([]RepositorySummary, 0)
	for id, repo := range s.repositories {
		threats := s.mappedThreats[id]
		repos = append(repos, RepositorySummary{
			ID:            id,
			URL:           repo.URL,
			Language:      repo.Language,
			Framework:     repo.Framework,
			ThreatCount:   len(threats),
			AssetCount:    len(repo.Assets),
			CriticalCount: countBySeverity(threats, models.SeverityCritical),
		})
	}

	json.NewEncoder(w).Encode(repos)
}

func (s *Server) handleAPIRepository(w http.ResponseWriter, r *http.Request) {
	repoID := r.URL.Path[len("/api/repository/"):]

	s.mu.RLock()
	repo, exists := s.repositories[repoID]
	s.mu.RUnlock()

	if !exists {
		http.Error(w, "Repository not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(repo)
}

func (s *Server) handleAPIThreats(w http.ResponseWriter, r *http.Request) {
	repoID := r.URL.Path[len("/api/threats/"):]

	s.mu.RLock()
	threats, exists := s.mappedThreats[repoID]
	s.mu.RUnlock()

	if !exists {
		http.Error(w, "Repository not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(threats)
}

func (s *Server) handleAPIAssets(w http.ResponseWriter, r *http.Request) {
	repoID := r.URL.Path[len("/api/assets/"):]

	s.mu.RLock()
	repo, exists := s.repositories[repoID]
	s.mu.RUnlock()

	if !exists {
		http.Error(w, "Repository not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(repo.Assets)
}

func (s *Server) handleAPIFlows(w http.ResponseWriter, r *http.Request) {
	repoID := r.URL.Path[len("/api/flows/"):]

	s.mu.RLock()
	repo, exists := s.repositories[repoID]
	s.mu.RUnlock()

	if !exists {
		http.Error(w, "Repository not found", http.StatusNotFound)
		return
	}

	// Convert flows to graph format for visualization
	graph := convertFlowsToGraph(repo.DataFlows, repo.Assets)
	json.NewEncoder(w).Encode(graph)
}

func (s *Server) handleAPIMitigations(w http.ResponseWriter, r *http.Request) {
	repoID := r.URL.Path[len("/api/mitigations/"):]

	s.mu.RLock()
	threats, exists := s.mappedThreats[repoID]
	s.mu.RUnlock()

	if !exists {
		http.Error(w, "Repository not found", http.StatusNotFound)
		return
	}

	// Collect all mitigations
	allMitigations := make([]mapper.Mitigation, 0)
	for _, threat := range threats {
		allMitigations = append(allMitigations, threat.Mitigations...)
	}

	json.NewEncoder(w).Encode(allMitigations)
}

// Data structures

type RepositorySummary struct {
	ID            string `json:"id"`
	URL           string `json:"url"`
	Language      string `json:"language"`
	Framework     string `json:"framework"`
	ThreatCount   int    `json:"threat_count"`
	AssetCount    int    `json:"asset_count"`
	CriticalCount int    `json:"critical_count"`
}

type RepositoryStats struct {
	TotalAssets       int            `json:"total_assets"`
	AssetsByType      map[string]int `json:"assets_by_type"`
	TotalThreats      int            `json:"total_threats"`
	ThreatsBySeverity map[string]int `json:"threats_by_severity"`
	TotalFlows        int            `json:"total_flows"`
	SensitiveFlows    int            `json:"sensitive_flows"`
	AverageRisk       float64        `json:"average_risk"`
}

type FlowGraph struct {
	Nodes []FlowNode `json:"nodes"`
	Links []FlowLink `json:"links"`
}

type FlowNode struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Type     string `json:"type"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Risky    bool   `json:"risky"`
}

type FlowLink struct {
	Source    string `json:"source"`
	Target    string `json:"target"`
	Sensitive bool   `json:"sensitive"`
	Label     string `json:"label"`
}

// Helper functions

func extractRepoID(url string) string {
	// Simple ID generation from URL
	parts := url[len(url)-20:]
	return parts
}

func countBySeverity(threats []mapper.MappedThreat, severity models.ThreatSeverity) int {
	count := 0
	for _, threat := range threats {
		if threat.Threat.Severity == severity {
			count++
		}
	}
	return count
}

func calculateStats(repo *scanner.Repository, threats []mapper.MappedThreat) RepositoryStats {
	stats := RepositoryStats{
		TotalAssets:       len(repo.Assets),
		AssetsByType:      make(map[string]int),
		TotalThreats:      len(threats),
		ThreatsBySeverity: make(map[string]int),
		TotalFlows:        len(repo.DataFlows),
	}

	// Count by asset type
	for _, asset := range repo.Assets {
		stats.AssetsByType[string(asset.Type)]++
	}

	// Count by severity
	for _, threat := range threats {
		stats.ThreatsBySeverity[string(threat.Threat.Severity)]++
	}

	// Count sensitive flows
	for _, flow := range repo.DataFlows {
		if flow.Sensitive {
			stats.SensitiveFlows++
		}
	}

	// Calculate average risk
	if len(threats) > 0 {
		totalRisk := 0.0
		for _, threat := range threats {
			totalRisk += threat.RiskScore
		}
		stats.AverageRisk = totalRisk / float64(len(threats))
	}

	return stats
}

func convertFlowsToGraph(flows []scanner.DataFlow, assets []scanner.Asset) FlowGraph {
	graph := FlowGraph{
		Nodes: make([]FlowNode, 0),
		Links: make([]FlowLink, 0),
	}

	nodeMap := make(map[string]bool)

	for _, flow := range flows {
		// Add source node
		sourceID := fmt.Sprintf("%s:%d", flow.Source.File, flow.Source.Line)
		if !nodeMap[sourceID] {
			graph.Nodes = append(graph.Nodes, FlowNode{
				ID:    sourceID,
				Label: flow.Source.Function,
				Type:  "source",
				File:  flow.Source.File,
				Line:  flow.Source.Line,
				Risky: flow.Sensitive,
			})
			nodeMap[sourceID] = true
		}

		// Add destination node
		destID := fmt.Sprintf("%s:%d", flow.Destination.File, flow.Destination.Line)
		if !nodeMap[destID] {
			graph.Nodes = append(graph.Nodes, FlowNode{
				ID:    destID,
				Label: flow.Destination.Function,
				Type:  "destination",
				File:  flow.Destination.File,
				Line:  flow.Destination.Line,
				Risky: flow.Sensitive,
			})
			nodeMap[destID] = true
		}

		// Add link
		graph.Links = append(graph.Links, FlowLink{
			Source:    sourceID,
			Target:    destID,
			Sensitive: flow.Sensitive,
			Label:     flow.DataType,
		})
	}

	return graph
}
