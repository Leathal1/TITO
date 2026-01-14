package scanner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Repository represents a scanned code repository
type Repository struct {
	URL          string    `json:"url"`
	LocalPath    string    `json:"local_path"`
	Branch       string    `json:"branch"`
	Language     string    `json:"language"`
	Framework    string    `json:"framework"`
	LastScanned  time.Time `json:"last_scanned"`
	Assets       []Asset   `json:"assets"`
	DataFlows    []DataFlow `json:"data_flows"`
	Dependencies []Dependency `json:"dependencies"`
}

// Asset represents a discoverable asset in the codebase
type Asset struct {
	ID          string   `json:"id"`
	Type        AssetType `json:"type"`
	Name        string   `json:"name"`
	Location    Location `json:"location"`
	Description string   `json:"description"`
	Sensitive   bool     `json:"sensitive"`
	Exposed     bool     `json:"exposed"`    // Internet-accessible
	Tags        []string `json:"tags"`
}

// AssetType represents types of assets we discover
type AssetType string

const (
	AssetAPI         AssetType = "api"
	AssetDatabase    AssetType = "database"
	AssetAuth        AssetType = "authentication"
	AssetSecret      AssetType = "secret"
	AssetFileSystem  AssetType = "filesystem"
	AssetNetwork     AssetType = "network"
	AssetCrypto      AssetType = "cryptography"
	AssetSession     AssetType = "session"
	AssetCache       AssetType = "cache"
	AssetQueue       AssetType = "queue"
)

// Location represents where something is in the code
type Location struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	Function string `json:"function"`
	Package  string `json:"package"`
}

// DataFlow represents data flowing through the system
type DataFlow struct {
	ID          string     `json:"id"`
	Source      Location   `json:"source"`
	Destination Location   `json:"destination"`
	DataType    string     `json:"data_type"`
	Sensitive   bool       `json:"sensitive"`
	Path        []Location `json:"path"`
	Threats     []string   `json:"threats"` // Threat IDs
}

// Dependency represents an external dependency
type Dependency struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Type    string   `json:"type"` // direct, transitive
	CVEs    []string `json:"cves"`
	License string   `json:"license"`
}

// Scanner scans repositories for assets and threats
type Scanner struct {
	workDir string
}

// NewScanner creates a new repository scanner
func NewScanner(workDir string) *Scanner {
	return &Scanner{
		workDir: workDir,
	}
}

// ScanRepository clones and scans a repository
func (s *Scanner) ScanRepository(ctx context.Context, repoURL, branch string) (*Repository, error) {
	// Create work directory
	if err := os.MkdirAll(s.workDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create work dir: %w", err)
	}

	// Clone repository
	repoName := extractRepoName(repoURL)
	localPath := filepath.Join(s.workDir, repoName)

	if err := s.cloneRepository(ctx, repoURL, localPath, branch); err != nil {
		return nil, fmt.Errorf("failed to clone repository: %w", err)
	}

	repo := &Repository{
		URL:         repoURL,
		LocalPath:   localPath,
		Branch:      branch,
		LastScanned: time.Now(),
	}

	// Detect language and framework
	if err := s.detectTechnology(repo); err != nil {
		return nil, fmt.Errorf("failed to detect technology: %w", err)
	}

	// Discover assets
	if err := s.discoverAssets(ctx, repo); err != nil {
		return nil, fmt.Errorf("failed to discover assets: %w", err)
	}

	// Analyze data flows
	if err := s.analyzeDataFlows(ctx, repo); err != nil {
		return nil, fmt.Errorf("failed to analyze data flows: %w", err)
	}

	// Extract dependencies
	if err := s.extractDependencies(ctx, repo); err != nil {
		return nil, fmt.Errorf("failed to extract dependencies: %w", err)
	}

	return repo, nil
}

// cloneRepository clones a git repository
func (s *Scanner) cloneRepository(ctx context.Context, repoURL, localPath, branch string) error {
	// Remove existing directory
	os.RemoveAll(localPath)

	// Clone repository
	args := []string{"clone", "--depth", "1"}
	if branch != "" {
		args = append(args, "--branch", branch)
	}
	args = append(args, repoURL, localPath)

	cmd := exec.CommandContext(ctx, "git", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git clone failed: %s: %w", string(output), err)
	}

	return nil
}

// detectTechnology detects the programming language and framework
func (s *Scanner) detectTechnology(repo *Repository) error {
	// Check for language indicators
	indicators := map[string][]string{
		"go":         {"go.mod", "go.sum", "main.go"},
		"python":     {"requirements.txt", "setup.py", "pyproject.toml", "Pipfile"},
		"javascript": {"package.json", "node_modules"},
		"typescript": {"tsconfig.json", "package.json"},
		"java":       {"pom.xml", "build.gradle", "gradle.properties"},
		"ruby":       {"Gemfile", "Rakefile"},
		"rust":       {"Cargo.toml", "Cargo.lock"},
		"php":        {"composer.json", "composer.lock"},
	}

	for lang, files := range indicators {
		for _, file := range files {
			path := filepath.Join(repo.LocalPath, file)
			if _, err := os.Stat(path); err == nil {
				repo.Language = lang
				break
			}
		}
		if repo.Language != "" {
			break
		}
	}

	// Detect framework
	repo.Framework = s.detectFramework(repo)

	return nil
}

// detectFramework detects the framework used
func (s *Scanner) detectFramework(repo *Repository) string {
	// Framework detection logic based on language
	switch repo.Language {
	case "go":
		// Check for popular Go frameworks
		goMod := filepath.Join(repo.LocalPath, "go.mod")
		data, err := os.ReadFile(goMod)
		if err == nil {
			content := string(data)
			if strings.Contains(content, "gin-gonic/gin") {
				return "gin"
			} else if strings.Contains(content, "labstack/echo") {
				return "echo"
			} else if strings.Contains(content, "gorilla/mux") {
				return "gorilla"
			} else if strings.Contains(content, "fiber") {
				return "fiber"
			}
		}
		return "stdlib"

	case "python":
		// Check requirements.txt or imports
		reqFile := filepath.Join(repo.LocalPath, "requirements.txt")
		data, err := os.ReadFile(reqFile)
		if err == nil {
			content := string(data)
			if strings.Contains(content, "django") {
				return "django"
			} else if strings.Contains(content, "flask") {
				return "flask"
			} else if strings.Contains(content, "fastapi") {
				return "fastapi"
			}
		}

	case "javascript", "typescript":
		pkgFile := filepath.Join(repo.LocalPath, "package.json")
		data, err := os.ReadFile(pkgFile)
		if err == nil {
			content := string(data)
			if strings.Contains(content, "\"react\"") {
				return "react"
			} else if strings.Contains(content, "\"express\"") {
				return "express"
			} else if strings.Contains(content, "\"next\"") {
				return "nextjs"
			} else if strings.Contains(content, "\"vue\"") {
				return "vue"
			}
		}
	}

	return "unknown"
}

// discoverAssets discovers assets in the codebase
func (s *Scanner) discoverAssets(ctx context.Context, repo *Repository) error {
	assets := make([]Asset, 0)

	// Walk the repository
	err := filepath.Walk(repo.LocalPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip hidden directories and vendor/node_modules
		if info.IsDir() {
			name := info.Name()
			if strings.HasPrefix(name, ".") || name == "vendor" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}

		// Only scan code files
		if !isCodeFile(path) {
			return nil
		}

		// Read file
		content, err := os.ReadFile(path)
		if err != nil {
			return nil // Skip files we can't read
		}

		// Scan for assets
		relPath, _ := filepath.Rel(repo.LocalPath, path)
		fileAssets := s.scanFileForAssets(relPath, string(content), repo.Language)
		assets = append(assets, fileAssets...)

		return nil
	})

	if err != nil {
		return err
	}

	repo.Assets = assets
	return nil
}

// scanFileForAssets scans a file for assets
func (s *Scanner) scanFileForAssets(filePath, content, language string) []Asset {
	assets := make([]Asset, 0)

	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		// API endpoints
		if strings.Contains(line, "http.HandleFunc") ||
			strings.Contains(line, ".GET(") ||
			strings.Contains(line, ".POST(") ||
			strings.Contains(line, "@app.route") ||
			strings.Contains(line, "@router") {

			assets = append(assets, Asset{
				ID:       fmt.Sprintf("api-%s-%d", filePath, lineNum),
				Type:     AssetAPI,
				Name:     extractAPIPath(line),
				Location: Location{File: filePath, Line: lineNum + 1},
				Exposed:  true,
				Tags:     []string{"http", "endpoint"},
			})
		}

		// Database operations
		if strings.Contains(line, "db.Query") ||
			strings.Contains(line, "db.Exec") ||
			strings.Contains(line, "SELECT") ||
			strings.Contains(line, "INSERT") ||
			strings.Contains(line, "UPDATE") ||
			strings.Contains(line, "DELETE FROM") {

			assets = append(assets, Asset{
				ID:        fmt.Sprintf("db-%s-%d", filePath, lineNum),
				Type:      AssetDatabase,
				Name:      "Database Operation",
				Location:  Location{File: filePath, Line: lineNum + 1},
				Sensitive: true,
				Tags:      []string{"database", "sql"},
			})
		}

		// Authentication
		if strings.Contains(line, "auth") ||
			strings.Contains(line, "login") ||
			strings.Contains(line, "password") ||
			strings.Contains(line, "jwt") ||
			strings.Contains(line, "token") {

			assets = append(assets, Asset{
				ID:        fmt.Sprintf("auth-%s-%d", filePath, lineNum),
				Type:      AssetAuth,
				Name:      "Authentication Point",
				Location:  Location{File: filePath, Line: lineNum + 1},
				Sensitive: true,
				Tags:      []string{"auth", "security"},
			})
		}

		// Secrets (potential)
		if strings.Contains(line, "API_KEY") ||
			strings.Contains(line, "SECRET") ||
			strings.Contains(line, "PASSWORD") ||
			strings.Contains(line, "private_key") {

			assets = append(assets, Asset{
				ID:        fmt.Sprintf("secret-%s-%d", filePath, lineNum),
				Type:      AssetSecret,
				Name:      "Potential Secret",
				Location:  Location{File: filePath, Line: lineNum + 1},
				Sensitive: true,
				Tags:      []string{"secret", "credential"},
			})
		}
	}

	return assets
}

// analyzeDataFlows analyzes data flows through the code
func (s *Scanner) analyzeDataFlows(ctx context.Context, repo *Repository) error {
	// Simplified data flow analysis
	// Real implementation would use AST parsing
	flows := make([]DataFlow, 0)

	// Find HTTP handler -> Database flows
	apiAssets := filterAssets(repo.Assets, AssetAPI)
	dbAssets := filterAssets(repo.Assets, AssetDatabase)

	for _, api := range apiAssets {
		for _, db := range dbAssets {
			// If in same file or nearby, likely a flow
			if api.Location.File == db.Location.File {
				flows = append(flows, DataFlow{
					ID:          fmt.Sprintf("flow-%s-%s", api.ID, db.ID),
					Source:      api.Location,
					Destination: db.Location,
					DataType:    "user_input",
					Sensitive:   true,
					Path:        []Location{api.Location, db.Location},
					Threats:     []string{}, // Will be populated by mapper
				})
			}
		}
	}

	repo.DataFlows = flows
	return nil
}

// extractDependencies extracts project dependencies
func (s *Scanner) extractDependencies(ctx context.Context, repo *Repository) error {
	deps := make([]Dependency, 0)

	switch repo.Language {
	case "go":
		goMod := filepath.Join(repo.LocalPath, "go.mod")
		data, err := os.ReadFile(goMod)
		if err == nil {
			deps = parseGoMod(string(data))
		}

	case "python":
		reqFile := filepath.Join(repo.LocalPath, "requirements.txt")
		data, err := os.ReadFile(reqFile)
		if err == nil {
			deps = parseRequirementsTxt(string(data))
		}

	case "javascript", "typescript":
		pkgFile := filepath.Join(repo.LocalPath, "package.json")
		// Would parse package.json here
		_ = pkgFile
	}

	repo.Dependencies = deps
	return nil
}

// Helper functions

func extractRepoName(url string) string {
	parts := strings.Split(url, "/")
	name := parts[len(parts)-1]
	return strings.TrimSuffix(name, ".git")
}

func isCodeFile(path string) bool {
	ext := filepath.Ext(path)
	codeExts := []string{".go", ".py", ".js", ".ts", ".java", ".rb", ".php", ".rs", ".c", ".cpp", ".h"}
	for _, codeExt := range codeExts {
		if ext == codeExt {
			return true
		}
	}
	return false
}

func extractAPIPath(line string) string {
	// Simple extraction - real implementation would be more sophisticated
	for _, quote := range []string{`"`, `'`, "`"} {
		if strings.Contains(line, quote) {
			parts := strings.Split(line, quote)
			if len(parts) >= 2 {
				for _, part := range parts {
					if strings.HasPrefix(part, "/") {
						return part
					}
				}
			}
		}
	}
	return "unknown"
}

func filterAssets(assets []Asset, assetType AssetType) []Asset {
	filtered := make([]Asset, 0)
	for _, asset := range assets {
		if asset.Type == assetType {
			filtered = append(filtered, asset)
		}
	}
	return filtered
}

func parseGoMod(content string) []Dependency {
	deps := make([]Dependency, 0)
	lines := strings.Split(content, "\n")
	inRequire := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "require") {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}
		if inRequire && line != "" && !strings.HasPrefix(line, "//") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				deps = append(deps, Dependency{
					Name:    parts[0],
					Version: parts[1],
					Type:    "direct",
				})
			}
		}
	}

	return deps
}

func parseRequirementsTxt(content string) []Dependency {
	deps := make([]Dependency, 0)
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse package==version or package>=version
		name := line
		version := ""
		for _, sep := range []string{"==", ">=", "<=", "~=", ">", "<"} {
			if strings.Contains(line, sep) {
				parts := strings.Split(line, sep)
				name = strings.TrimSpace(parts[0])
				if len(parts) > 1 {
					version = strings.TrimSpace(parts[1])
				}
				break
			}
		}

		deps = append(deps, Dependency{
			Name:    name,
			Version: version,
			Type:    "direct",
		})
	}

	return deps
}
