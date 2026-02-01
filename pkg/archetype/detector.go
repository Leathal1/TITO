package archetype

import (
	"os"
	"path/filepath"
	"strings"
)

// Detector analyzes a repository to determine its architecture type
type Detector struct {
	repoPath string
}

// NewDetector creates a new architecture detector
func NewDetector(repoPath string) *Detector {
	return &Detector{
		repoPath: repoPath,
	}
}

// Detect analyzes the repository and returns an architecture profile
func (d *Detector) Detect(language, framework string) (*ArchProfile, error) {
	profile := &ArchProfile{
		PrimaryType:    ArchUnknown,
		SecondaryTypes: []ArchType{},
		Signals:        []Signal{},
	}

	// Run all detection methods
	d.detectFromProjectStructure(profile)
	d.detectFromDependencies(profile, language)
	d.detectFromFilePatterns(profile)
	d.detectFromCodePatterns(profile, language)
	d.detectFromConfig(profile)

	// Determine primary and secondary types
	d.determinePrimaryType(profile)
	d.determineSecondaryTypes(profile)

	// Calculate final confidence
	profile.Confidence = profile.CalculateConfidence()

	// Generate description
	profile.Description = profile.GenerateDescription(language, framework)

	return profile, nil
}

// detectFromProjectStructure analyzes directory structure
func (d *Detector) detectFromProjectStructure(profile *ArchProfile) {
	// Count cmd/ directories (Go pattern for multiple services)
	cmdDirs := d.countDirectories("cmd")
	if cmdDirs > 1 {
		profile.AddSignal(Signal{
			Type:        SignalProjectStructure,
			Description: "Multiple cmd/ directories indicate microservices",
			Evidence:    "multiple cmd directories",
			Weight:      0.8,
			ArchType:    ArchMicroservices,
		})
	} else if cmdDirs == 1 {
		// Single cmd/ could be CLI or monolith
		profile.AddSignal(Signal{
			Type:        SignalProjectStructure,
			Description: "Single cmd/ directory",
			Evidence:    "single cmd directory",
			Weight:      0.3,
			ArchType:    ArchMonolith,
		})
	}

	// Check for services/ directory
	if d.hasDirectory("services") {
		profile.AddSignal(Signal{
			Type:        SignalProjectStructure,
			Description: "Services directory indicates microservices",
			Evidence:    "services/ directory",
			Weight:      0.8,
			ArchType:    ArchMicroservices,
		})
	}

	// Check for pkg/ or lib/ without main
	hasPkg := d.hasDirectory("pkg") || d.hasDirectory("lib")
	hasMain := d.hasFile("main.go") || d.hasFile("main.py") || d.hasFile("index.js") || d.hasFile("index.ts")
	
	if hasPkg && !hasMain {
		profile.AddSignal(Signal{
			Type:        SignalProjectStructure,
			Description: "Library structure (pkg/lib without main)",
			Evidence:    "pkg or lib directory without main",
			Weight:      0.7,
			ArchType:    ArchLibrary,
		})
	}

	// Check for lambda/ or functions/ directories
	if d.hasDirectory("lambda") || d.hasDirectory("functions") {
		profile.AddSignal(Signal{
			Type:        SignalProjectStructure,
			Description: "Lambda/functions directory",
			Evidence:    "serverless function directories",
			Weight:      0.7,
			ArchType:    ArchServerless,
		})
	}

	// Check for frontend directories (web app indicator)
	frontendDirs := []string{"frontend", "client", "web", "ui", "public"}
	for _, dir := range frontendDirs {
		if d.hasDirectory(dir) {
			profile.AddSignal(Signal{
				Type:        SignalProjectStructure,
				Description: "Frontend directory indicates web application",
				Evidence:    dir + "/ directory",
				Weight:      0.6,
				ArchType:    ArchWebApp,
			})
			break
		}
	}

	// Check for data pipeline directories
	pipelineDirs := []string{"pipelines", "etl", "dags", "airflow"}
	for _, dir := range pipelineDirs {
		if d.hasDirectory(dir) {
			profile.AddSignal(Signal{
				Type:        SignalProjectStructure,
				Description: "Data pipeline directory",
				Evidence:    dir + "/ directory",
				Weight:      0.7,
				ArchType:    ArchDataPipeline,
			})
			break
		}
	}

	// Check for ML directories
	mlDirs := []string{"models", "training", "notebooks", "data"}
	mlCount := 0
	for _, dir := range mlDirs {
		if d.hasDirectory(dir) {
			mlCount++
		}
	}
	if mlCount >= 2 {
		profile.AddSignal(Signal{
			Type:        SignalProjectStructure,
			Description: "ML project structure",
			Evidence:    "multiple ML directories",
			Weight:      0.6,
			ArchType:    ArchAIML,
		})
	}
}

// detectFromDependencies analyzes dependencies in manifest files
func (d *Detector) detectFromDependencies(profile *ArchProfile, language string) {
	var content string
	var err error

	switch language {
	case "go":
		content, err = d.readFile("go.mod")
	case "python":
		// Try requirements.txt first
		content, err = d.readFile("requirements.txt")
		if err != nil {
			content, err = d.readFile("Pipfile")
		}
		if err != nil {
			content, err = d.readFile("pyproject.toml")
		}
	case "javascript", "typescript":
		content, err = d.readFile("package.json")
	case "java":
		content, err = d.readFile("pom.xml")
		if err != nil {
			content, err = d.readFile("build.gradle")
		}
	case "ruby":
		content, err = d.readFile("Gemfile")
	case "rust":
		content, err = d.readFile("Cargo.toml")
	}

	if err != nil {
		return
	}

	lower := strings.ToLower(content)

	// gRPC/Protobuf - strong microservices/API signal
	if strings.Contains(lower, "grpc") || strings.Contains(lower, "protobuf") || strings.Contains(lower, "proto") {
		profile.AddSignal(Signal{
			Type:        SignalDependency,
			Description: "gRPC dependency",
			Evidence:    "gRPC",
			Weight:      0.8,
			ArchType:    ArchMicroservices,
		})
		profile.AddSignal(Signal{
			Type:        SignalDependency,
			Description: "gRPC indicates API service",
			Evidence:    "gRPC",
			Weight:      0.7,
			ArchType:    ArchAPIService,
		})
	}

	// Web frameworks
	webFrameworks := map[string][]string{
		"express":  {"express", "expressjs"},
		"fastapi":  {"fastapi"},
		"flask":    {"flask"},
		"django":   {"django"},
		"gin":      {"gin-gonic", "gin"},
		"echo":     {"labstack/echo"},
		"fiber":    {"gofiber", "fiber"},
		"rails":    {"rails"},
		"spring":   {"spring-boot", "springframework"},
		"nextjs":   {"next"},
		"react":    {"react"},
		"vue":      {"vue"},
		"angular":  {"angular", "@angular"},
	}

	for framework, patterns := range webFrameworks {
		for _, pattern := range patterns {
			if strings.Contains(lower, pattern) {
				archType := ArchAPIService
				if framework == "nextjs" || framework == "react" || framework == "vue" || framework == "angular" {
					archType = ArchWebApp
				}
				profile.AddSignal(Signal{
					Type:        SignalDependency,
					Description: "Web framework: " + framework,
					Evidence:    framework,
					Weight:      0.7,
					ArchType:    archType,
				})
				break
			}
		}
	}

	// Serverless frameworks
	serverlessDeps := []string{
		"aws-lambda", "lambda", "azure-functions",
		"google-cloud-functions", "serverless", "chalice",
		"zappa", "claudia", "apex",
	}
	for _, dep := range serverlessDeps {
		if strings.Contains(lower, dep) {
			profile.AddSignal(Signal{
				Type:        SignalDependency,
				Description: "Serverless dependency: " + dep,
				Evidence:    dep,
				Weight:      0.9,
				ArchType:    ArchServerless,
			})
			break
		}
	}

	// Message queues - microservices/data pipeline
	queueDeps := []string{
		"kafka", "rabbitmq", "amqp", "nats",
		"redis", "celery", "bull", "sidekiq",
	}
	for _, dep := range queueDeps {
		if strings.Contains(lower, dep) {
			profile.AddSignal(Signal{
				Type:        SignalDependency,
				Description: "Message queue: " + dep,
				Evidence:    dep,
				Weight:      0.7,
				ArchType:    ArchMicroservices,
			})
			profile.AddSignal(Signal{
				Type:        SignalDependency,
				Description: "Message queue indicates data pipeline",
				Evidence:    dep,
				Weight:      0.6,
				ArchType:    ArchDataPipeline,
			})
			break
		}
	}

	// AI/ML frameworks
	mlDeps := []string{
		"tensorflow", "torch", "pytorch", "transformers",
		"langchain", "openai", "anthropic", "huggingface",
		"scikit-learn", "sklearn", "keras", "jax",
		"lightgbm", "xgboost", "mlflow",
	}
	for _, dep := range mlDeps {
		if strings.Contains(lower, dep) {
			profile.AddSignal(Signal{
				Type:        SignalDependency,
				Description: "ML framework: " + dep,
				Evidence:    dep,
				Weight:      0.9,
				ArchType:    ArchAIML,
			})
			break
		}
	}

	// Data processing
	dataDeps := []string{
		"apache-airflow", "airflow", "prefect", "dagster",
		"spark", "pyspark", "hadoop", "dask", "pandas",
	}
	for _, dep := range dataDeps {
		if strings.Contains(lower, dep) {
			profile.AddSignal(Signal{
				Type:        SignalDependency,
				Description: "Data processing: " + dep,
				Evidence:    dep,
				Weight:      0.8,
				ArchType:    ArchDataPipeline,
			})
			break
		}
	}

	// Mobile backend signals
	mobileDeps := []string{
		"firebase", "fcm", "apns", "push-notifications",
		"expo", "react-native", "flutter",
	}
	for _, dep := range mobileDeps {
		if strings.Contains(lower, dep) {
			profile.AddSignal(Signal{
				Type:        SignalDependency,
				Description: "Mobile SDK: " + dep,
				Evidence:    dep,
				Weight:      0.7,
				ArchType:    ArchMobileBackend,
			})
			break
		}
	}

	// CLI frameworks
	cliDeps := []string{
		"cobra", "click", "argparse", "clap",
		"commander", "yargs", "oclif",
	}
	hasHTTP := strings.Contains(lower, "http") || strings.Contains(lower, "express") || 
		strings.Contains(lower, "gin") || strings.Contains(lower, "fastapi")
	
	for _, dep := range cliDeps {
		if strings.Contains(lower, dep) && !hasHTTP {
			profile.AddSignal(Signal{
				Type:        SignalDependency,
				Description: "CLI framework: " + dep,
				Evidence:    dep,
				Weight:      0.8,
				ArchType:    ArchCLI,
			})
			break
		}
	}
}

// detectFromFilePatterns analyzes file patterns
func (d *Detector) detectFromFilePatterns(profile *ArchProfile) {
	// Count Dockerfiles
	dockerfileCount := d.countFiles("Dockerfile")
	if dockerfileCount > 2 {
		profile.AddSignal(Signal{
			Type:        SignalFilePattern,
			Description: "Multiple Dockerfiles indicate microservices",
			Evidence:    "multiple Dockerfiles",
			Weight:      0.8,
			ArchType:    ArchMicroservices,
		})
	}

	// Check docker-compose.yml
	if d.hasFile("docker-compose.yml") || d.hasFile("docker-compose.yaml") {
		content, err := d.readFile("docker-compose.yml")
		if err != nil {
			content, _ = d.readFile("docker-compose.yaml")
		}
		if content != "" {
			serviceCount := strings.Count(content, "services:")
			// Count service definitions
			lines := strings.Split(content, "\n")
			services := 0
			inServices := false
			for _, line := range lines {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "services:") {
					inServices = true
					continue
				}
				if inServices && strings.HasSuffix(trimmed, ":") && !strings.HasPrefix(trimmed, " ") {
					services++
				}
			}
			
			if services >= 3 {
				profile.AddSignal(Signal{
					Type:        SignalFilePattern,
					Description: "docker-compose with multiple services",
					Evidence:    "docker-compose with multiple services",
					Weight:      0.9,
					ArchType:    ArchMicroservices,
				})
			} else if serviceCount > 0 {
				profile.AddSignal(Signal{
					Type:        SignalFilePattern,
					Description: "docker-compose present",
					Evidence:    "docker-compose.yml",
					Weight:      0.4,
					ArchType:    ArchMonolith,
				})
			}
		}
	}

	// Kubernetes/Helm
	if d.hasDirectory("kubernetes") || d.hasDirectory("k8s") || d.hasDirectory("helm") {
		profile.AddSignal(Signal{
			Type:        SignalFilePattern,
			Description: "Kubernetes manifests",
			Evidence:    "kubernetes configuration",
			Weight:      0.8,
			ArchType:    ArchMicroservices,
		})
	}

	// Serverless configs
	serverlessConfigs := []string{
		"serverless.yml", "serverless.yaml",
		"template.yaml", "template.yml", // SAM
		"firebase.json",
	}
	for _, config := range serverlessConfigs {
		if d.hasFile(config) {
			profile.AddSignal(Signal{
				Type:        SignalConfig,
				Description: "Serverless config: " + config,
				Evidence:    config,
				Weight:      0.9,
				ArchType:    ArchServerless,
			})
			break
		}
	}

	// Terraform with Lambda/Functions
	if d.hasDirectory("terraform") {
		tfContent := d.readDirectoryFiles("terraform", ".tf")
		if strings.Contains(strings.ToLower(tfContent), "aws_lambda") ||
			strings.Contains(strings.ToLower(tfContent), "google_cloudfunctions") ||
			strings.Contains(strings.ToLower(tfContent), "azurerm_function_app") {
			profile.AddSignal(Signal{
				Type:        SignalConfig,
				Description: "Terraform with serverless functions",
				Evidence:    "terraform serverless",
				Weight:      0.9,
				ArchType:    ArchServerless,
			})
		}
	}

	// Jupyter notebooks - ML signal
	if d.countFiles(".ipynb") > 0 {
		profile.AddSignal(Signal{
			Type:        SignalFilePattern,
			Description: "Jupyter notebooks",
			Evidence:    ".ipynb files",
			Weight:      0.6,
			ArchType:    ArchAIML,
		})
	}

	// Proto files - microservices
	if d.countFiles(".proto") > 0 {
		profile.AddSignal(Signal{
			Type:        SignalFilePattern,
			Description: "Protocol buffer definitions",
			Evidence:    ".proto files",
			Weight:      0.7,
			ArchType:    ArchMicroservices,
		})
	}
}

// detectFromCodePatterns scans for code patterns (lightweight)
func (d *Detector) detectFromCodePatterns(profile *ArchProfile, language string) {
	// This is intentionally lightweight - just check a few key files
	// Full code analysis is expensive and done elsewhere

	var mainFiles []string
	switch language {
	case "go":
		mainFiles = []string{"main.go", "cmd/main.go"}
	case "python":
		mainFiles = []string{"main.py", "app.py", "__main__.py"}
	case "javascript", "typescript":
		mainFiles = []string{"index.js", "index.ts", "server.js", "app.js"}
	}

	hasHTTPServer := false
	hasCLIParser := false

	for _, file := range mainFiles {
		content, err := d.readFile(file)
		if err != nil {
			// Try in cmd/ directory
			content, err = d.readFile(filepath.Join("cmd", file))
		}
		if err != nil {
			continue
		}

		lower := strings.ToLower(content)

		// HTTP server patterns
		httpPatterns := []string{
			"http.listenandserve", "app.listen", "server.listen",
			"uvicorn.run", "app.run", "serve(",
		}
		for _, pattern := range httpPatterns {
			if strings.Contains(lower, pattern) {
				hasHTTPServer = true
				break
			}
		}

		// CLI patterns
		cliPatterns := []string{
			"flag.parse", "argparse", "click.command",
			"cobra.command", "clap.app", "args.parse",
		}
		for _, pattern := range cliPatterns {
			if strings.Contains(lower, pattern) {
				hasCLIParser = true
				break
			}
		}
	}

	if hasHTTPServer && !hasCLIParser {
		profile.AddSignal(Signal{
			Type:        SignalCodePattern,
			Description: "HTTP server initialization",
			Evidence:    "HTTP server code",
			Weight:      0.6,
			ArchType:    ArchAPIService,
		})
	}

	if hasCLIParser && !hasHTTPServer {
		profile.AddSignal(Signal{
			Type:        SignalCodePattern,
			Description: "CLI argument parsing without HTTP",
			Evidence:    "CLI parser code",
			Weight:      0.7,
			ArchType:    ArchCLI,
		})
	}
}

// detectFromConfig analyzes configuration files
func (d *Detector) detectFromConfig(profile *ArchProfile) {
	// Check Makefile targets
	makefileContent, err := d.readFile("Makefile")
	if err == nil {
		lower := strings.ToLower(makefileContent)
		if strings.Contains(lower, "deploy-lambda") || strings.Contains(lower, "deploy-function") {
			profile.AddSignal(Signal{
				Type:        SignalConfig,
				Description: "Makefile with serverless deploy targets",
				Evidence:    "serverless Makefile targets",
				Weight:      0.6,
				ArchType:    ArchServerless,
			})
		}
	}

	// Check GitHub Actions workflows
	workflowsPath := filepath.Join(".github", "workflows")
	if d.hasDirectory(workflowsPath) {
		workflows := d.readDirectoryFiles(workflowsPath, ".yml")
		workflows += d.readDirectoryFiles(workflowsPath, ".yaml")
		lower := strings.ToLower(workflows)
		
		if strings.Contains(lower, "aws-actions/amazon-ecr-login") || 
		   strings.Contains(lower, "docker/build-push-action") {
			// Container deployment suggests microservices or monolith
			if strings.Count(workflows, "docker build") > 2 {
				profile.AddSignal(Signal{
					Type:        SignalConfig,
					Description: "Multiple Docker builds in CI",
					Evidence:    "CI/CD patterns",
					Weight:      0.5,
					ArchType:    ArchMicroservices,
				})
			}
		}

		if strings.Contains(lower, "serverless deploy") ||
		   strings.Contains(lower, "sam deploy") {
			profile.AddSignal(Signal{
				Type:        SignalConfig,
				Description: "Serverless deployment in CI",
				Evidence:    "CI/CD patterns",
				Weight:      0.7,
				ArchType:    ArchServerless,
			})
		}
	}
}

// determinePrimaryType selects the primary architecture type based on signals
func (d *Detector) determinePrimaryType(profile *ArchProfile) {
	// Count weighted votes for each architecture type
	votes := make(map[ArchType]float64)
	
	for _, signal := range profile.Signals {
		votes[signal.ArchType] += signal.Weight
	}

	// Find the architecture with highest vote
	maxVote := 0.0
	primaryType := ArchUnknown
	
	for archType, vote := range votes {
		if vote > maxVote {
			maxVote = vote
			primaryType = archType
		}
	}

	// Require minimum confidence threshold
	if maxVote >= 0.5 {
		profile.PrimaryType = primaryType
	} else {
		// Default to monolith if uncertain but has some API indicators
		if votes[ArchAPIService] > 0 {
			profile.PrimaryType = ArchMonolith
		} else {
			profile.PrimaryType = ArchUnknown
		}
	}
}

// determineSecondaryTypes identifies secondary architecture characteristics
func (d *Detector) determineSecondaryTypes(profile *ArchProfile) {
	// Count votes again, excluding primary
	votes := make(map[ArchType]float64)
	
	for _, signal := range profile.Signals {
		if signal.ArchType != profile.PrimaryType {
			votes[signal.ArchType] += signal.Weight
		}
	}

	// Add secondary types that have significant votes
	for archType, vote := range votes {
		if vote >= 0.4 { // Lower threshold for secondary
			profile.SecondaryTypes = append(profile.SecondaryTypes, archType)
		}
	}
}

// Helper methods

func (d *Detector) hasFile(filename string) bool {
	path := filepath.Join(d.repoPath, filename)
	_, err := os.Stat(path)
	return err == nil
}

func (d *Detector) hasDirectory(dirname string) bool {
	path := filepath.Join(d.repoPath, dirname)
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func (d *Detector) readFile(filename string) (string, error) {
	path := filepath.Join(d.repoPath, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (d *Detector) countDirectories(dirName string) int {
	count := 0
	filepath.Walk(d.repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() && info.Name() == dirName {
			count++
		}
		return nil
	})
	return count
}

func (d *Detector) countFiles(extension string) int {
	count := 0
	filepath.Walk(d.repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && (strings.HasSuffix(info.Name(), extension) || info.Name() == extension) {
			count++
		}
		return nil
	})
	return count
}

func (d *Detector) readDirectoryFiles(dir string, extension string) string {
	var content strings.Builder
	dirPath := filepath.Join(d.repoPath, dir)
	
	filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), extension) {
			data, err := os.ReadFile(path)
			if err == nil {
				content.WriteString(string(data))
				content.WriteString("\n")
			}
		}
		return nil
	})
	
	return content.String()
}
