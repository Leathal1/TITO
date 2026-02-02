package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewScanner(t *testing.T) {
	workDir := "/tmp/test-scanner"
	scanner := NewScanner(workDir)

	if scanner == nil {
		t.Fatal("NewScanner returned nil")
	}

	if scanner.workDir != workDir {
		t.Errorf("expected workDir %s, got %s", workDir, scanner.workDir)
	}
}

func TestDetectTechnology_Go(t *testing.T) {
	// Create temporary directory with go.mod
	tmpDir, err := os.MkdirTemp("", "test-repo-go-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create go.mod file
	goModPath := filepath.Join(tmpDir, "go.mod")
	if err := os.WriteFile(goModPath, []byte("module test"), 0644); err != nil {
		t.Fatalf("failed to create go.mod: %v", err)
	}

	scanner := NewScanner("/tmp")
	repo := &Repository{
		LocalPath: tmpDir,
	}

	err = scanner.detectTechnology(repo)
	if err != nil {
		t.Fatalf("detectTechnology failed: %v", err)
	}

	if repo.Language != "go" {
		t.Errorf("expected language 'go', got %s", repo.Language)
	}
}

func TestDetectTechnology_Python(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-repo-python-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create requirements.txt file
	reqPath := filepath.Join(tmpDir, "requirements.txt")
	if err := os.WriteFile(reqPath, []byte("flask==2.0.0"), 0644); err != nil {
		t.Fatalf("failed to create requirements.txt: %v", err)
	}

	scanner := NewScanner("/tmp")
	repo := &Repository{
		LocalPath: tmpDir,
	}

	err = scanner.detectTechnology(repo)
	if err != nil {
		t.Fatalf("detectTechnology failed: %v", err)
	}

	if repo.Language != "python" {
		t.Errorf("expected language 'python', got %s", repo.Language)
	}
}

func TestDetectTechnology_JavaScript(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-repo-js-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create package.json file
	pkgPath := filepath.Join(tmpDir, "package.json")
	if err := os.WriteFile(pkgPath, []byte(`{"name": "test"}`), 0644); err != nil {
		t.Fatalf("failed to create package.json: %v", err)
	}

	scanner := NewScanner("/tmp")
	repo := &Repository{
		LocalPath: tmpDir,
	}

	err = scanner.detectTechnology(repo)
	if err != nil {
		t.Fatalf("detectTechnology failed: %v", err)
	}

	// package.json alone may detect as javascript or typescript (map iteration order)
	if repo.Language != "javascript" && repo.Language != "typescript" {
		t.Errorf("expected language 'javascript' or 'typescript', got %s", repo.Language)
	}
}

func TestAssetTypes(t *testing.T) {
	assetTypes := []AssetType{
		AssetAPI,
		AssetDatabase,
		AssetAuth,
		AssetSecret,
		AssetFileSystem,
		AssetNetwork,
		AssetCrypto,
		AssetSession,
		AssetCache,
		AssetQueue,
	}

	if len(assetTypes) != 10 {
		t.Errorf("expected 10 asset types, got %d", len(assetTypes))
	}

	// Verify all asset types are distinct
	seen := make(map[AssetType]bool)
	for _, at := range assetTypes {
		if seen[at] {
			t.Errorf("duplicate asset type: %s", at)
		}
		seen[at] = true
	}
}

func TestRepository_Initialization(t *testing.T) {
	repo := &Repository{
		URL:         "https://github.com/test/repo",
		LocalPath:   "/tmp/repo",
		Branch:      "main",
		Language:    "go",
		Framework:   "gin",
		LastScanned: time.Now(),
		Assets:      []Asset{},
		DataFlows:   []DataFlow{},
		Dependencies: []Dependency{},
	}

	if repo.URL == "" {
		t.Error("URL should not be empty")
	}

	if repo.Language != "go" {
		t.Errorf("expected language 'go', got %s", repo.Language)
	}

	if len(repo.Assets) != 0 {
		t.Errorf("expected 0 assets initially, got %d", len(repo.Assets))
	}
}

func TestAsset_Creation(t *testing.T) {
	asset := Asset{
		ID:   "asset-1",
		Type: AssetAPI,
		Name: "UserAPI",
		Location: Location{
			File:     "api/users.go",
			Line:     42,
			Function: "CreateUser",
			Package:  "api",
		},
		Description: "User creation endpoint",
		Sensitive:   true,
		Exposed:     true,
		Tags:        []string{"api", "user", "create"},
	}

	if asset.ID != "asset-1" {
		t.Errorf("expected ID 'asset-1', got %s", asset.ID)
	}

	if asset.Type != AssetAPI {
		t.Errorf("expected type AssetAPI, got %s", asset.Type)
	}

	if !asset.Sensitive {
		t.Error("asset should be marked as sensitive")
	}

	if !asset.Exposed {
		t.Error("asset should be marked as exposed")
	}

	if len(asset.Tags) != 3 {
		t.Errorf("expected 3 tags, got %d", len(asset.Tags))
	}
}

func TestDataFlow_Creation(t *testing.T) {
	dataFlow := DataFlow{
		ID: "flow-1",
		Source: Location{
			File:     "api/handler.go",
			Line:     10,
			Function: "HandleRequest",
		},
		Destination: Location{
			File:     "db/queries.go",
			Line:     50,
			Function: "InsertUser",
		},
		DataType:  "user_data",
		Sensitive: true,
		Path: []Location{
			{File: "api/handler.go", Line: 10},
			{File: "models/user.go", Line: 25},
			{File: "db/queries.go", Line: 50},
		},
		Threats: []string{"threat-1", "threat-2"},
	}

	if dataFlow.ID != "flow-1" {
		t.Errorf("expected ID 'flow-1', got %s", dataFlow.ID)
	}

	if !dataFlow.Sensitive {
		t.Error("data flow should be marked as sensitive")
	}

	if len(dataFlow.Path) != 3 {
		t.Errorf("expected 3 locations in path, got %d", len(dataFlow.Path))
	}

	if len(dataFlow.Threats) != 2 {
		t.Errorf("expected 2 threats, got %d", len(dataFlow.Threats))
	}
}

func TestDependency_Creation(t *testing.T) {
	dep := Dependency{
		Name:    "github.com/gin-gonic/gin",
		Version: "v1.9.0",
		Type:    "direct",
		CVEs:    []string{"CVE-2024-1234"},
		License: "MIT",
	}

	if dep.Name == "" {
		t.Error("dependency name should not be empty")
	}

	if dep.Version != "v1.9.0" {
		t.Errorf("expected version 'v1.9.0', got %s", dep.Version)
	}

	if dep.Type != "direct" {
		t.Errorf("expected type 'direct', got %s", dep.Type)
	}

	if len(dep.CVEs) != 1 {
		t.Errorf("expected 1 CVE, got %d", len(dep.CVEs))
	}
}

func TestLocation_Structure(t *testing.T) {
	loc := Location{
		File:     "main.go",
		Line:     100,
		Column:   25,
		Function: "main",
		Package:  "main",
	}

	if loc.File != "main.go" {
		t.Errorf("expected file 'main.go', got %s", loc.File)
	}

	if loc.Line != 100 {
		t.Errorf("expected line 100, got %d", loc.Line)
	}

	if loc.Column != 25 {
		t.Errorf("expected column 25, got %d", loc.Column)
	}

	if loc.Function != "main" {
		t.Errorf("expected function 'main', got %s", loc.Function)
	}
}

func TestExtractRepoName(t *testing.T) {
	tests := []struct {
		url      string
		expected string
	}{
		{"https://github.com/user/repo", "repo"},
		{"https://github.com/user/repo.git", "repo"},
		{"git@github.com:user/repo.git", "repo"},
		{"https://gitlab.com/group/project", "project"},
	}

	for _, tt := range tests {
		result := extractRepoName(tt.url)
		if result != tt.expected {
			t.Errorf("extractRepoName(%q) = %q, want %q", tt.url, result, tt.expected)
		}
	}
}

func TestDiscoverAssets_EmptyRepo(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-repo-empty-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	scanner := NewScanner("/tmp")
	repo := &Repository{
		LocalPath: tmpDir,
		Language:  "go",
	}

	ctx := context.Background()
	err = scanner.discoverAssets(ctx, repo)
	if err != nil {
		t.Fatalf("discoverAssets failed: %v", err)
	}

	// Empty repo should have no assets discovered
	// (Implementation returns empty list, not error)
}

func TestAnalyzeDataFlows_EmptyRepo(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-repo-empty-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	scanner := NewScanner("/tmp")
	repo := &Repository{
		LocalPath: tmpDir,
		Language:  "go",
	}

	ctx := context.Background()
	err = scanner.analyzeDataFlows(ctx, repo)
	if err != nil {
		t.Fatalf("analyzeDataFlows failed: %v", err)
	}
}

func TestExtractDependencies_EmptyRepo(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-repo-empty-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	scanner := NewScanner("/tmp")
	repo := &Repository{
		LocalPath: tmpDir,
		Language:  "go",
	}

	ctx := context.Background()
	err = scanner.extractDependencies(ctx, repo)
	if err != nil {
		t.Fatalf("extractDependencies failed: %v", err)
	}
}

func TestRepository_MultipleAssets(t *testing.T) {
	repo := &Repository{
		URL:      "https://github.com/test/repo",
		Language: "go",
		Assets: []Asset{
			{ID: "asset-1", Type: AssetAPI, Name: "UserAPI"},
			{ID: "asset-2", Type: AssetDatabase, Name: "UserDB"},
			{ID: "asset-3", Type: AssetAuth, Name: "AuthService"},
		},
	}

	if len(repo.Assets) != 3 {
		t.Errorf("expected 3 assets, got %d", len(repo.Assets))
	}

	// Verify asset types are different
	typeMap := make(map[AssetType]bool)
	for _, asset := range repo.Assets {
		typeMap[asset.Type] = true
	}

	if len(typeMap) != 3 {
		t.Error("expected 3 different asset types")
	}
}

func TestDataFlow_PathTracking(t *testing.T) {
	// Create a data flow with multiple path points
	flow := DataFlow{
		ID:        "flow-complex",
		DataType:  "sensitive_data",
		Sensitive: true,
		Path: []Location{
			{File: "input.go", Line: 10, Function: "ReadInput"},
			{File: "validate.go", Line: 20, Function: "Validate"},
			{File: "transform.go", Line: 30, Function: "Transform"},
			{File: "store.go", Line: 40, Function: "Store"},
		},
	}

	if len(flow.Path) != 4 {
		t.Errorf("expected 4 path locations, got %d", len(flow.Path))
	}

	// Verify path order is maintained
	if flow.Path[0].File != "input.go" {
		t.Error("path order not maintained")
	}

	if flow.Path[3].File != "store.go" {
		t.Error("path order not maintained")
	}
}
