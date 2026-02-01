package scanner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Leathal1/TITO/pkg/archetype"
)

// Repository represents a scanned code repository
type Repository struct {
	URL          string                `json:"url"`
	LocalPath    string                `json:"local_path"`
	Branch       string                `json:"branch"`
	Language     string                `json:"language"`
	Framework    string                `json:"framework"`
	Architecture *archetype.ArchProfile `json:"architecture,omitempty"`
	LastScanned  time.Time             `json:"last_scanned"`
	Assets       []Asset               `json:"assets"`
	DataFlows    []DataFlow            `json:"data_flows"`
	Dependencies []Dependency          `json:"dependencies"`
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

	// Detect architecture
	if err := s.detectArchitecture(repo); err != nil {
		return nil, fmt.Errorf("failed to detect architecture: %w", err)
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

// detectArchitecture detects the application architecture type
func (s *Scanner) detectArchitecture(repo *Repository) error {
	detector := archetype.NewDetector(repo.LocalPath)
	profile, err := detector.Detect(repo.Language, repo.Framework)
	if err != nil {
		return err
	}
	repo.Architecture = profile
	return nil
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
		lowerLine := strings.ToLower(line)
		trimmedLine := strings.TrimSpace(line)

		// Skip comments and empty lines
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "//") || strings.HasPrefix(trimmedLine, "#") {
			continue
		}

		// API Endpoints - extensive patterns
		apiPatterns := []string{
			"http.HandleFunc", "http.Handle", "mux.HandleFunc",
			"router.GET", "router.POST", "router.PUT", "router.DELETE", "router.PATCH",
			".GET(", ".POST(", ".PUT(", ".DELETE(", ".PATCH(",
			"app.get", "app.post", "app.put", "app.delete", "app.patch",
			"@app.route", "@router", "@GetMapping", "@PostMapping", "@PutMapping", "@DeleteMapping",
			"@RequestMapping", "Route(", "MapGet", "MapPost",
			"express.get", "express.post", "fastapi", "flask.route",
		}
		for _, pattern := range apiPatterns {
			if strings.Contains(lowerLine, strings.ToLower(pattern)) {
				assets = append(assets, Asset{
					ID:          fmt.Sprintf("api-%s-%d", filePath, lineNum),
					Type:        AssetAPI,
					Name:        extractAPIPath(line),
					Location:    Location{File: filePath, Line: lineNum + 1},
					Description: fmt.Sprintf("HTTP endpoint: %s", trimmedLine),
					Exposed:     true,
					Sensitive:   detectSensitiveContext(line),
					Tags:        []string{"http", "endpoint", "api"},
				})
				break
			}
		}

		// Database connections and queries
		dbPatterns := []string{
			"db.Query", "db.Exec", "db.Prepare", "database/sql",
			"sqlx.", "gorm", ".Create(", ".Save(", ".Update(", ".Delete(",
			"mongoose.connect", "mongoose.model", "Schema(",
			"pg.connect", "psycopg2", "pymongo", "redis.client",
			"SELECT ", "INSERT ", "UPDATE ", "DELETE FROM", "CREATE TABLE",
			"DROP TABLE", "ALTER TABLE", "TRUNCATE",
			"sql.Open", "sql.DB", "Sequelize", "TypeORM",
		}
		for _, pattern := range dbPatterns {
			if strings.Contains(lowerLine, strings.ToLower(pattern)) {
				assets = append(assets, Asset{
					ID:          fmt.Sprintf("db-%s-%d", filePath, lineNum),
					Type:        AssetDatabase,
					Name:        extractDatabaseOperation(line),
					Location:    Location{File: filePath, Line: lineNum + 1},
					Description: fmt.Sprintf("Database operation: %s", trimmedLine),
					Sensitive:   true,
					Tags:        []string{"database", "sql", "persistence"},
				})
				break
			}
		}

		// Authentication and authorization
		authPatterns := []string{
			"jwt.sign", "jwt.verify", "jsonwebtoken", "passport",
			"bcrypt", "scrypt", "argon2", "pbkdf2",
			"OAuth", "oauth2", "openid", "saml",
			".Authenticate", "CheckPassword", "ValidateToken",
			"middleware.Auth", "@RequiresAuth", "@Secured",
			"session.set", "session.get", "express-session",
			".login", ".logout", ".signin", ".signout",
		}
		for _, pattern := range authPatterns {
			if strings.Contains(lowerLine, strings.ToLower(pattern)) {
				assets = append(assets, Asset{
					ID:          fmt.Sprintf("auth-%s-%d", filePath, lineNum),
					Type:        AssetAuth,
					Name:        extractAuthMethod(line),
					Location:    Location{File: filePath, Line: lineNum + 1},
					Description: fmt.Sprintf("Authentication: %s", trimmedLine),
					Sensitive:   true,
					Tags:        []string{"auth", "security", "identity"},
				})
				break
			}
		}

		// File I/O operations
		filePatterns := []string{
			"os.Open", "os.Create", "os.ReadFile", "os.WriteFile",
			"ioutil.ReadFile", "ioutil.WriteFile",
			"fs.readFile", "fs.writeFile", "fs.createReadStream",
			"open(", "file.open", "with open",
			"FileReader", "FileWriter", "BufferedReader",
			"upload", "multipart", "formidable",
		}
		for _, pattern := range filePatterns {
			if strings.Contains(lowerLine, strings.ToLower(pattern)) {
				assets = append(assets, Asset{
					ID:          fmt.Sprintf("file-%s-%d", filePath, lineNum),
					Type:        AssetFileSystem,
					Name:        "File Operation",
					Location:    Location{File: filePath, Line: lineNum + 1},
					Description: fmt.Sprintf("File I/O: %s", trimmedLine),
					Sensitive:   strings.Contains(lowerLine, "upload") || strings.Contains(lowerLine, "write"),
					Tags:        []string{"file", "io", "storage"},
				})
				break
			}
		}

		// External API calls
		externalAPIPatterns := []string{
			"http.Get", "http.Post", "http.Client",
			"fetch(", "axios.", "request(",
			"requests.get", "requests.post", "urllib",
			"HttpClient", "RestTemplate", "WebClient",
			"curl_exec", "curl_init",
		}
		for _, pattern := range externalAPIPatterns {
			if strings.Contains(lowerLine, strings.ToLower(pattern)) {
				assets = append(assets, Asset{
					ID:          fmt.Sprintf("extapi-%s-%d", filePath, lineNum),
					Type:        AssetNetwork,
					Name:        "External API Call",
					Location:    Location{File: filePath, Line: lineNum + 1},
					Description: fmt.Sprintf("External call: %s", trimmedLine),
					Exposed:     false,
					Sensitive:   detectSensitiveContext(line),
					Tags:        []string{"external", "api", "network"},
				})
				break
			}
		}

		// Environment variables
		envPatterns := []string{
			"os.Getenv", "process.env", "System.getenv",
			"ENV[", "ENV.fetch", "$ENV{",
			"dotenv", "envfile", ".env",
		}
		for _, pattern := range envPatterns {
			if strings.Contains(lowerLine, strings.ToLower(pattern)) {
				assets = append(assets, Asset{
					ID:          fmt.Sprintf("env-%s-%d", filePath, lineNum),
					Type:        AssetSecret,
					Name:        extractEnvVar(line),
					Location:    Location{File: filePath, Line: lineNum + 1},
					Description: fmt.Sprintf("Environment variable: %s", trimmedLine),
					Sensitive:   true,
					Tags:        []string{"config", "environment", "secret"},
				})
				break
			}
		}

		// Secrets and credentials
		secretPatterns := []string{
			"api_key", "apikey", "api-key",
			"secret", "password", "passwd", "pwd",
			"private_key", "privatekey", "token",
			"credentials", "auth_token", "access_key",
			"client_secret", "encryption_key",
		}
		for _, pattern := range secretPatterns {
			if strings.Contains(lowerLine, pattern) && (strings.Contains(line, "=") || strings.Contains(line, ":")) {
				assets = append(assets, Asset{
					ID:          fmt.Sprintf("secret-%s-%d", filePath, lineNum),
					Type:        AssetSecret,
					Name:        fmt.Sprintf("Secret: %s", pattern),
					Location:    Location{File: filePath, Line: lineNum + 1},
					Description: fmt.Sprintf("Potential secret: %s", trimmedLine),
					Sensitive:   true,
					Tags:        []string{"secret", "credential", "sensitive"},
				})
				break
			}
		}

		// Message queues
		queuePatterns := []string{
			"kafka", "rabbitmq", "amqp",
			"redis.publish", "redis.subscribe",
			"sqs", "sns", "pubsub",
			"messagequeue", "eventbus",
		}
		for _, pattern := range queuePatterns {
			if strings.Contains(lowerLine, pattern) {
				assets = append(assets, Asset{
					ID:          fmt.Sprintf("queue-%s-%d", filePath, lineNum),
					Type:        AssetQueue,
					Name:        fmt.Sprintf("Message Queue: %s", pattern),
					Location:    Location{File: filePath, Line: lineNum + 1},
					Description: fmt.Sprintf("Queue operation: %s", trimmedLine),
					Tags:        []string{"queue", "messaging", "async"},
				})
				break
			}
		}

		// Caching
		cachePatterns := []string{
			"redis", "memcached", "cache.set", "cache.get",
			"@Cacheable", "CacheManager",
		}
		for _, pattern := range cachePatterns {
			if strings.Contains(lowerLine, strings.ToLower(pattern)) {
				assets = append(assets, Asset{
					ID:       fmt.Sprintf("cache-%s-%d", filePath, lineNum),
					Type:     AssetCache,
					Name:     "Cache Operation",
					Location: Location{File: filePath, Line: lineNum + 1},
					Tags:     []string{"cache", "performance"},
				})
				break
			}
		}

		// Cryptography
		cryptoPatterns := []string{
			"crypto/", "cryptography", "cipher",
			"aes", "rsa", "ecdsa", "hmac",
			"encrypt", "decrypt", "hash",
		}
		for _, pattern := range cryptoPatterns {
			if strings.Contains(lowerLine, strings.ToLower(pattern)) {
				assets = append(assets, Asset{
					ID:          fmt.Sprintf("crypto-%s-%d", filePath, lineNum),
					Type:        AssetCrypto,
					Name:        "Cryptographic Operation",
					Location:    Location{File: filePath, Line: lineNum + 1},
					Description: fmt.Sprintf("Crypto: %s", trimmedLine),
					Sensitive:   true,
					Tags:        []string{"crypto", "security", "encryption"},
				})
				break
			}
		}
	}

	// Also scan for .env files
	if strings.HasSuffix(filePath, ".env") || strings.Contains(filePath, ".env.") {
		for lineNum, line := range lines {
			if strings.Contains(line, "=") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					key := strings.TrimSpace(parts[0])
					assets = append(assets, Asset{
						ID:          fmt.Sprintf("envvar-%s-%s", filePath, key),
						Type:        AssetSecret,
						Name:        fmt.Sprintf("ENV: %s", key),
						Location:    Location{File: filePath, Line: lineNum + 1},
						Description: fmt.Sprintf("Environment variable: %s", key),
						Sensitive:   true,
						Tags:        []string{"environment", "config", "secret"},
					})
				}
			}
		}
	}

	return assets
}

// Helper function to detect sensitive context
func detectSensitiveContext(line string) bool {
	sensitiveKeywords := []string{
		"password", "secret", "token", "key", "credential",
		"auth", "payment", "credit", "ssn", "personal",
	}
	lowerLine := strings.ToLower(line)
	for _, keyword := range sensitiveKeywords {
		if strings.Contains(lowerLine, keyword) {
			return true
		}
	}
	return false
}

// Extract more specific names
func extractAuthMethod(line string) string {
	if strings.Contains(line, "jwt") {
		return "JWT Authentication"
	} else if strings.Contains(line, "oauth") {
		return "OAuth Authentication"
	} else if strings.Contains(line, "bcrypt") {
		return "Password Hashing (bcrypt)"
	} else if strings.Contains(line, "session") {
		return "Session Management"
	}
	return "Authentication"
}

func extractDatabaseOperation(line string) string {
	lower := strings.ToLower(line)
	if strings.Contains(lower, "select") {
		return "Database Query (SELECT)"
	} else if strings.Contains(lower, "insert") {
		return "Database Insert"
	} else if strings.Contains(lower, "update") {
		return "Database Update"
	} else if strings.Contains(lower, "delete") {
		return "Database Delete"
	} else if strings.Contains(lower, "connect") {
		return "Database Connection"
	}
	return "Database Operation"
}

func extractEnvVar(line string) string {
	// Try to extract the actual variable name
	if strings.Contains(line, "\"") {
		parts := strings.Split(line, "\"")
		if len(parts) >= 2 {
			return fmt.Sprintf("ENV: %s", parts[1])
		}
	}
	return "Environment Variable"
}

// analyzeDataFlows analyzes data flows through the code
func (s *Scanner) analyzeDataFlows(ctx context.Context, repo *Repository) error {
	flows := make([]DataFlow, 0)
	flowMap := make(map[string]bool) // Deduplicate flows

	// Group assets by file for proximity analysis
	assetsByFile := make(map[string][]Asset)
	for _, asset := range repo.Assets {
		assetsByFile[asset.Location.File] = append(assetsByFile[asset.Location.File], asset)
	}

	// Flow 1: API -> Database (user input to persistence)
	apiAssets := filterAssets(repo.Assets, AssetAPI)
	dbAssets := filterAssets(repo.Assets, AssetDatabase)
	for _, api := range apiAssets {
		for _, db := range dbAssets {
			if api.Location.File == db.Location.File {
				flowID := fmt.Sprintf("flow-api-db-%s-%s", api.ID, db.ID)
				if !flowMap[flowID] {
					flowMap[flowID] = true
					flows = append(flows, DataFlow{
						ID:          flowID,
						Source:      api.Location,
						Destination: db.Location,
						DataType:    "user_data",
						Sensitive:   true,
						Path:        []Location{api.Location, db.Location},
						Threats:     []string{"SQL Injection", "Data Tampering"},
					})
				}
			}
		}
	}

	// Flow 2: API -> External API (proxying/forwarding)
	extAssets := filterAssets(repo.Assets, AssetNetwork)
	for _, api := range apiAssets {
		for _, ext := range extAssets {
			if api.Location.File == ext.Location.File {
				flowID := fmt.Sprintf("flow-api-ext-%s-%s", api.ID, ext.ID)
				if !flowMap[flowID] {
					flowMap[flowID] = true
					flows = append(flows, DataFlow{
						ID:          flowID,
						Source:      api.Location,
						Destination: ext.Location,
						DataType:    "forwarded_request",
						Sensitive:   api.Sensitive || ext.Sensitive,
						Path:        []Location{api.Location, ext.Location},
						Threats:     []string{"SSRF", "Data Leakage"},
					})
				}
			}
		}
	}

	// Flow 3: Authentication -> API (protected endpoints)
	authAssets := filterAssets(repo.Assets, AssetAuth)
	for _, auth := range authAssets {
		for _, api := range apiAssets {
			if auth.Location.File == api.Location.File &&
				abs(auth.Location.Line-api.Location.Line) < 50 {
				flowID := fmt.Sprintf("flow-auth-api-%s-%s", auth.ID, api.ID)
				if !flowMap[flowID] {
					flowMap[flowID] = true
					flows = append(flows, DataFlow{
						ID:          flowID,
						Source:      auth.Location,
						Destination: api.Location,
						DataType:    "authenticated_request",
						Sensitive:   true,
						Path:        []Location{auth.Location, api.Location},
						Threats:     []string{"Broken Authentication", "Session Hijacking"},
					})
				}
			}
		}
	}

	// Flow 4: File I/O from API (uploads)
	fileAssets := filterAssets(repo.Assets, AssetFileSystem)
	for _, api := range apiAssets {
		for _, file := range fileAssets {
			if api.Location.File == file.Location.File {
				flowID := fmt.Sprintf("flow-api-file-%s-%s", api.ID, file.ID)
				if !flowMap[flowID] {
					flowMap[flowID] = true
					flows = append(flows, DataFlow{
						ID:          flowID,
						Source:      api.Location,
						Destination: file.Location,
						DataType:    "file_upload",
						Sensitive:   true,
						Path:        []Location{api.Location, file.Location},
						Threats:     []string{"Path Traversal", "Arbitrary File Upload"},
					})
				}
			}
		}
	}

	// Flow 5: Environment variables -> Config -> Services
	envAssets := filterAssets(repo.Assets, AssetSecret)
	for _, env := range envAssets {
		// Find usage in same or nearby files
		for file, assets := range assetsByFile {
			for _, asset := range assets {
				if asset.Type != AssetSecret && 
					(file == env.Location.File || 
					strings.Contains(file, "config") || 
					strings.Contains(file, "setup")) {
					flowID := fmt.Sprintf("flow-env-svc-%s-%s", env.ID, asset.ID)
					if !flowMap[flowID] {
						flowMap[flowID] = true
						flows = append(flows, DataFlow{
							ID:          flowID,
							Source:      env.Location,
							Destination: asset.Location,
							DataType:    "configuration",
							Sensitive:   true,
							Path:        []Location{env.Location, asset.Location},
							Threats:     []string{"Secret Exposure", "Configuration Tampering"},
						})
					}
				}
			}
		}
	}

	// Flow 6: Database -> Cache (read-through caching)
	cacheAssets := filterAssets(repo.Assets, AssetCache)
	for _, db := range dbAssets {
		for _, cache := range cacheAssets {
			if db.Location.File == cache.Location.File {
				flowID := fmt.Sprintf("flow-db-cache-%s-%s", db.ID, cache.ID)
				if !flowMap[flowID] {
					flowMap[flowID] = true
					flows = append(flows, DataFlow{
						ID:          flowID,
						Source:      db.Location,
						Destination: cache.Location,
						DataType:    "cached_data",
						Sensitive:   db.Sensitive,
						Path:        []Location{db.Location, cache.Location},
						Threats:     []string{"Cache Poisoning", "Data Exposure"},
					})
				}
			}
		}
	}

	// Flow 7: Queue producers and consumers
	queueAssets := filterAssets(repo.Assets, AssetQueue)
	for _, api := range apiAssets {
		for _, queue := range queueAssets {
			if api.Location.File == queue.Location.File {
				flowID := fmt.Sprintf("flow-api-queue-%s-%s", api.ID, queue.ID)
				if !flowMap[flowID] {
					flowMap[flowID] = true
					flows = append(flows, DataFlow{
						ID:          flowID,
						Source:      api.Location,
						Destination: queue.Location,
						DataType:    "async_message",
						Sensitive:   api.Sensitive,
						Path:        []Location{api.Location, queue.Location},
						Threats:     []string{"Message Injection", "Replay Attacks"},
					})
				}
			}
		}
	}

	// Flow 8: Crypto operations on sensitive data
	cryptoAssets := filterAssets(repo.Assets, AssetCrypto)
	for _, crypto := range cryptoAssets {
		// Find sensitive assets in proximity
		if assets, ok := assetsByFile[crypto.Location.File]; ok {
			for _, asset := range assets {
				if asset.Sensitive && asset.Type != AssetCrypto {
					flowID := fmt.Sprintf("flow-data-crypto-%s-%s", asset.ID, crypto.ID)
					if !flowMap[flowID] {
						flowMap[flowID] = true
						flows = append(flows, DataFlow{
							ID:          flowID,
							Source:      asset.Location,
							Destination: crypto.Location,
							DataType:    "encrypted_data",
							Sensitive:   true,
							Path:        []Location{asset.Location, crypto.Location},
							Threats:     []string{"Weak Cryptography", "Key Management"},
						})
					}
				}
			}
		}
	}

	repo.DataFlows = flows
	return nil
}

// Helper function for absolute difference
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
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
		// Try requirements.txt
		reqFile := filepath.Join(repo.LocalPath, "requirements.txt")
		data, err := os.ReadFile(reqFile)
		if err == nil {
			deps = parseRequirementsTxt(string(data))
		}
		// Try Pipfile
		if len(deps) == 0 {
			pipFile := filepath.Join(repo.LocalPath, "Pipfile")
			data, err := os.ReadFile(pipFile)
			if err == nil {
				deps = parsePipfile(string(data))
			}
		}

	case "javascript", "typescript":
		pkgFile := filepath.Join(repo.LocalPath, "package.json")
		data, err := os.ReadFile(pkgFile)
		if err == nil {
			deps = parsePackageJSON(string(data))
		}

	case "ruby":
		gemFile := filepath.Join(repo.LocalPath, "Gemfile")
		data, err := os.ReadFile(gemFile)
		if err == nil {
			deps = parseGemfile(string(data))
		}

	case "java":
		// Try pom.xml
		pomFile := filepath.Join(repo.LocalPath, "pom.xml")
		data, err := os.ReadFile(pomFile)
		if err == nil {
			deps = parsePomXML(string(data))
		}
		// Try build.gradle
		if len(deps) == 0 {
			gradleFile := filepath.Join(repo.LocalPath, "build.gradle")
			data, err := os.ReadFile(gradleFile)
			if err == nil {
				deps = parseBuildGradle(string(data))
			}
		}

	case "rust":
		cargoFile := filepath.Join(repo.LocalPath, "Cargo.toml")
		data, err := os.ReadFile(cargoFile)
		if err == nil {
			deps = parseCargoToml(string(data))
		}
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

func parsePipfile(content string) []Dependency {
	deps := make([]Dependency, 0)
	lines := strings.Split(content, "\n")
	inPackages := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[packages]") {
			inPackages = true
			continue
		}
		if strings.HasPrefix(line, "[") {
			inPackages = false
		}
		if inPackages && strings.Contains(line, "=") {
			parts := strings.Split(line, "=")
			if len(parts) >= 2 {
				name := strings.TrimSpace(parts[0])
				version := strings.Trim(strings.TrimSpace(parts[1]), "\"'")
				deps = append(deps, Dependency{
					Name:    name,
					Version: version,
					Type:    "direct",
				})
			}
		}
	}

	return deps
}

func parsePackageJSON(content string) []Dependency {
	deps := make([]Dependency, 0)
	
	// Simple JSON parsing for dependencies
	lines := strings.Split(content, "\n")
	inDeps := false
	
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "\"dependencies\"") || strings.Contains(trimmed, "\"devDependencies\"") {
			inDeps = true
			continue
		}
		if inDeps && trimmed == "}" {
			inDeps = false
			continue
		}
		if inDeps && strings.Contains(trimmed, ":") {
			// Parse "package": "^1.2.3"
			parts := strings.Split(trimmed, ":")
			if len(parts) >= 2 {
				name := strings.Trim(strings.TrimSpace(parts[0]), "\",")
				version := strings.Trim(strings.TrimSpace(parts[1]), "\",^~")
				deps = append(deps, Dependency{
					Name:    name,
					Version: version,
					Type:    "direct",
				})
			}
		}
	}

	return deps
}

func parseGemfile(content string) []Dependency {
	deps := make([]Dependency, 0)
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gem ") {
			// Parse gem 'name', '~> 1.2.3'
			parts := strings.Split(line, "'")
			if len(parts) >= 2 {
				name := parts[1]
				version := ""
				if len(parts) >= 4 {
					version = strings.TrimSpace(parts[3])
					version = strings.TrimPrefix(version, "~> ")
				}
				deps = append(deps, Dependency{
					Name:    name,
					Version: version,
					Type:    "direct",
				})
			}
		}
	}

	return deps
}

func parsePomXML(content string) []Dependency {
	deps := make([]Dependency, 0)
	lines := strings.Split(content, "\n")

	var currentName, currentVersion string
	inDependency := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "<dependency>") {
			inDependency = true
			currentName = ""
			currentVersion = ""
		}
		if strings.Contains(trimmed, "</dependency>") {
			if currentName != "" {
				deps = append(deps, Dependency{
					Name:    currentName,
					Version: currentVersion,
					Type:    "direct",
				})
			}
			inDependency = false
		}
		if inDependency {
			if strings.Contains(trimmed, "<artifactId>") {
				currentName = extractXMLValue(trimmed, "artifactId")
			}
			if strings.Contains(trimmed, "<version>") {
				currentVersion = extractXMLValue(trimmed, "version")
			}
		}
	}

	return deps
}

func parseBuildGradle(content string) []Dependency {
	deps := make([]Dependency, 0)
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Parse implementation 'group:artifact:version'
		if strings.Contains(trimmed, "implementation") || 
		   strings.Contains(trimmed, "compile") ||
		   strings.Contains(trimmed, "api") {
			if strings.Contains(trimmed, "'") || strings.Contains(trimmed, "\"") {
				parts := strings.FieldsFunc(trimmed, func(r rune) bool {
					return r == '\'' || r == '"'
				})
				if len(parts) >= 2 {
					depParts := strings.Split(parts[1], ":")
					if len(depParts) >= 2 {
						name := depParts[0] + ":" + depParts[1]
						version := ""
						if len(depParts) >= 3 {
							version = depParts[2]
						}
						deps = append(deps, Dependency{
							Name:    name,
							Version: version,
							Type:    "direct",
						})
					}
				}
			}
		}
	}

	return deps
}

func parseCargoToml(content string) []Dependency {
	deps := make([]Dependency, 0)
	lines := strings.Split(content, "\n")
	inDeps := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[dependencies]") {
			inDeps = true
			continue
		}
		if strings.HasPrefix(trimmed, "[") {
			inDeps = false
		}
		if inDeps && strings.Contains(trimmed, "=") {
			parts := strings.Split(trimmed, "=")
			if len(parts) >= 2 {
				name := strings.TrimSpace(parts[0])
				version := strings.Trim(strings.TrimSpace(parts[1]), "\"'{}")
				deps = append(deps, Dependency{
					Name:    name,
					Version: version,
					Type:    "direct",
				})
			}
		}
	}

	return deps
}

func extractXMLValue(line, tag string) string {
	openTag := "<" + tag + ">"
	closeTag := "</" + tag + ">"
	start := strings.Index(line, openTag)
	end := strings.Index(line, closeTag)
	if start >= 0 && end > start {
		return line[start+len(openTag) : end]
	}
	return ""
}
