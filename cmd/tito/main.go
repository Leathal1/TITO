package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Leathal1/TITO/pkg/collectors"
	"github.com/Leathal1/TITO/pkg/config"
	"github.com/Leathal1/TITO/pkg/dashboard"
	"github.com/Leathal1/TITO/pkg/dataflow"
	"github.com/Leathal1/TITO/pkg/maestro"
	"github.com/Leathal1/TITO/pkg/mapper"
	"github.com/Leathal1/TITO/pkg/mitre"
	"github.com/Leathal1/TITO/pkg/models"
	"github.com/Leathal1/TITO/pkg/pipeline"
	"github.com/Leathal1/TITO/pkg/reports"
	"github.com/Leathal1/TITO/pkg/scanner"
	"github.com/Leathal1/TITO/pkg/semgrep"
	"github.com/spf13/cobra"
)

var (
	cfgFile string
	cfg     *config.Config
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "tito",
	Short: "TITO - Advanced Threat Intelligence Platform",
	Long: `TITO - Advanced Threat Intelligence Platform

An intelligence organism that transforms chaos into actionable clarity.

The platform implements the STRIDE-LM framework for threat classification
and provides intelligent prioritization, enrichment, and reporting.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		var err error
		cfg, err = config.LoadOrDefault(cfgFile)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}
		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default: config.yaml)")

	rootCmd.AddCommand(initConfigCmd)
	rootCmd.AddCommand(collectCmd)
	rootCmd.AddCommand(reportCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(dashboardCmd)
	rootCmd.AddCommand(serveCmd)
}

var initConfigCmd = &cobra.Command{
	Use:   "init-config",
	Short: "Create a default configuration file",
	Long:  "Create a default configuration file with sensible defaults",
	RunE: func(cmd *cobra.Command, args []string) error {
		output, _ := cmd.Flags().GetString("output")
		if output == "" {
			output = "config.yaml"
		}

		err := config.CreateDefault(output)
		if err != nil {
			return fmt.Errorf("failed to create config: %w", err)
		}

		fmt.Printf("✓ Created configuration file at %s\n", output)
		fmt.Println("  Edit this file to customize TITO settings")
		return nil
	},
}

func init() {
	initConfigCmd.Flags().StringP("output", "o", "config.yaml", "Output path for config file")
}

var collectCmd = &cobra.Command{
	Use:   "collect",
	Short: "Collect threat intelligence from sources",
	Long: `Collect threat intelligence from configured sources.

Examples:
  tito collect --all              # Run all collectors
  tito collect --nvd              # Run only NVD collector
  tito collect --nvd --osint      # Run specific collectors`,
	RunE: runCollect,
}

func init() {
	collectCmd.Flags().BoolP("all", "a", false, "Run all collectors")
	collectCmd.Flags().Bool("nvd", false, "Run NVD collector")
	collectCmd.Flags().Bool("osint", false, "Run OSINT collector")
	collectCmd.Flags().StringP("output", "o", "", "Output file for collected threats (JSON)")
}

func runCollect(cmd *cobra.Command, args []string) error {
	collectAll, _ := cmd.Flags().GetBool("all")
	collectNVD, _ := cmd.Flags().GetBool("nvd")
	collectOSINT, _ := cmd.Flags().GetBool("osint")

	if !collectAll && !collectNVD && !collectOSINT {
		return fmt.Errorf("no collectors specified. Use --all, --nvd, or --osint")
	}

	var collectorsList []collectors.Collector

	// NVD collector
	if (collectAll || collectNVD) && cfg.Collectors.NVD.Enabled {
		nvdCollector := collectors.NewNVDCollector(cfg.Collectors.NVD.APIKey, cfg.Collectors.NVD.DaysBack)
		collectorsList = append(collectorsList, nvdCollector)
		fmt.Println("→ NVD collector enabled")
	}

	// OSINT collector would go here
	// if (collectAll || collectOSINT) && cfg.Collectors.OSINT.Enabled {
	// 	osintCollector := collectors.NewOSINTCollector(...)
	// 	collectorsList = append(collectorsList, osintCollector)
	// 	fmt.Println("→ OSINT collector enabled")
	// }

	if len(collectorsList) == 0 {
		return fmt.Errorf("no collectors enabled")
	}

	fmt.Println()
	fmt.Println("Starting collection...")
	fmt.Println()

	// Run collectors
	ctx := context.Background()
	allThreats := make([]*models.Threat, 0)

	for _, collector := range collectorsList {
		fmt.Printf("Running %s collector...\n", collector.Name())
		threats, err := collector.Collect(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %s failed: %v\n", collector.Name(), err)
			continue
		}
		allThreats = append(allThreats, threats...)
		fmt.Printf("  ✓ Collected %d threats from %s\n", len(threats), collector.Name())
	}

	fmt.Println()
	fmt.Printf("Total raw threats collected: %d\n", len(allThreats))

	// Process through pipeline
	fmt.Println()
	fmt.Println("Processing threats through pipeline...")

	processor := pipeline.NewProcessor(pipeline.ProcessorConfig{
		MinPriority: cfg.Pipeline.MinPriority,
		MaxAgeDays:  cfg.Pipeline.MaxAgeDays,
	})

	processedThreats, err := processor.Process(ctx, allThreats)
	if err != nil {
		return fmt.Errorf("pipeline processing failed: %w", err)
	}

	fmt.Printf("  ✓ Pipeline complete: %d threats remain\n", len(processedThreats))
	fmt.Println()

	// Show top threats
	if len(processedThreats) > 0 {
		fmt.Println("Top 5 threats by priority:")
		for i := 0; i < min(5, len(processedThreats)); i++ {
			threat := processedThreats[i]
			stride := ""
			if threat.StrideProfile != nil {
				stride = fmt.Sprintf(" [%s]", threat.StrideProfile)
			}
			fmt.Printf("  %d. [%s]%s %s (priority: %.2f)\n",
				i+1, threat.Severity, stride, truncate(threat.Title, 60), threat.PriorityScore)
		}
		fmt.Println()
	}

	// TODO: Save to JSON if output specified

	fmt.Println("Collection complete.")
	return nil
}

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate threat intelligence report",
	Long: `Generate a threat intelligence report from collected threats.

Examples:
  tito report                          # Generate markdown report
  tito report -f json -o report.json   # Generate JSON report`,
	RunE: runReport,
}

func init() {
	reportCmd.Flags().StringP("format", "f", "markdown", "Report format (markdown, json)")
	reportCmd.Flags().StringP("output", "o", "", "Output file path")
}

func runReport(cmd *cobra.Command, args []string) error {
	format, _ := cmd.Flags().GetString("format")
	output, _ := cmd.Flags().GetString("output")

	fmt.Println("Collecting fresh threat data...")

	// Run NVD collector
	ctx := context.Background()
	nvdCollector := collectors.NewNVDCollector(cfg.Collectors.NVD.APIKey, cfg.Collectors.NVD.DaysBack)
	threats, err := nvdCollector.Collect(ctx)
	if err != nil {
		return fmt.Errorf("collection failed: %w", err)
	}

	// Process through pipeline
	processor := pipeline.NewProcessor(pipeline.ProcessorConfig{
		MinPriority: cfg.Pipeline.MinPriority,
		MaxAgeDays:  cfg.Pipeline.MaxAgeDays,
	})

	processedThreats, err := processor.Process(ctx, threats)
	if err != nil {
		return fmt.Errorf("processing failed: %w", err)
	}

	if len(processedThreats) == 0 {
		return fmt.Errorf("no threats to report")
	}

	fmt.Println()
	fmt.Printf("Generating %s report...\n", format)

	if format == "markdown" {
		generator := reports.NewMarkdownGenerator(cfg.Reports.OutputDir)
		reportPath, err := generator.Generate(processedThreats, output)
		if err != nil {
			return fmt.Errorf("report generation failed: %w", err)
		}
		fmt.Printf("✓ Report generated: %s\n", reportPath)
	} else {
		return fmt.Errorf("format '%s' not yet implemented", format)
	}

	return nil
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show TITO system status",
	Long:  "Display the current status of the TITO system including configuration and collectors",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("TITO System Status")
		fmt.Println(strings.Repeat("=", 50))
		fmt.Println()

		fmt.Println("Configuration:")
		fmt.Printf("  Config file: %s\n", getConfigPath())
		fmt.Println()

		fmt.Println("Collectors:")
		fmt.Printf("  NVD:   %s\n", enabledStatus(cfg.Collectors.NVD.Enabled))
		fmt.Printf("  OSINT: %s\n", enabledStatus(cfg.Collectors.OSINT.Enabled))
		fmt.Println()

		fmt.Println("Pipeline:")
		fmt.Printf("  Min Priority: %.2f\n", cfg.Pipeline.MinPriority)
		fmt.Printf("  Max Age: %d days\n", cfg.Pipeline.MaxAgeDays)
		fmt.Println()

		fmt.Println("API:")
		fmt.Printf("  Status: %s\n", enabledStatus(cfg.API.Enabled))
		fmt.Printf("  Port: %d\n", cfg.API.Port)
		fmt.Println()

		return nil
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("TITO - Advanced Threat Intelligence Platform")
		fmt.Println("Version: 2.1.0")
		fmt.Println("Go implementation with STRIDE-LM framework + Repository Scanning")
	},
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a repository for threats and assets",
	Long: `Scan a code repository to discover assets, analyze data flows,
and map threats to specific code locations.

Examples:
  tito scan --repo https://github.com/user/repo
  tito scan --repo https://github.com/user/repo --branch main`,
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringP("repo", "r", "", "Repository URL to scan (required)")
	scanCmd.Flags().StringP("branch", "b", "", "Branch to scan (default: main)")
	scanCmd.Flags().Bool("maestro", false, "Enable MAESTRO agentic AI threat analysis")
	scanCmd.Flags().Bool("semgrep", false, "Enable Semgrep static analysis")
	scanCmd.Flags().Bool("dataflow", false, "Generate interactive data flow diagram HTML (2D)")
	scanCmd.Flags().Bool("3d", false, "Generate 3D data flow visualization")
	scanCmd.Flags().Bool("mitre", false, "Enrich findings with MITRE ATT&CK mappings")
	scanCmd.Flags().StringP("output", "o", "", "Output file for report/diagram")
	scanCmd.MarkFlagRequired("repo")
}

func runScan(cmd *cobra.Command, args []string) error {
	repoURL, _ := cmd.Flags().GetString("repo")
	branch, _ := cmd.Flags().GetString("branch")
	enableMAESTRO, _ := cmd.Flags().GetBool("maestro")
	enableSemgrep, _ := cmd.Flags().GetBool("semgrep")
	enableDataflow, _ := cmd.Flags().GetBool("dataflow")
	enable3D, _ := cmd.Flags().GetBool("3d")
	enableMITRE, _ := cmd.Flags().GetBool("mitre")
	outputFile, _ := cmd.Flags().GetString("output")

	if branch == "" {
		branch = "main"
	}

	fmt.Println("🔍 TITO Repository Scanner")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Println()

	// Step 1: Scan repository
	fmt.Printf("📂 Cloning repository: %s\n", repoURL)
	fmt.Printf("   Branch: %s\n", branch)
	fmt.Println()

	s := scanner.NewScanner("./work")
	ctx := context.Background()

	repo, err := s.ScanRepository(ctx, repoURL, branch)
	if err != nil {
		return fmt.Errorf("repository scan failed: %w", err)
	}

	fmt.Printf("✓ Repository scanned successfully\n")
	fmt.Printf("  Language: %s\n", repo.Language)
	fmt.Printf("  Framework: %s\n", repo.Framework)
	fmt.Printf("  Assets discovered: %d\n", len(repo.Assets))
	fmt.Printf("  Data flows: %d\n", len(repo.DataFlows))
	fmt.Printf("  Dependencies: %d\n", len(repo.Dependencies))
	fmt.Println()

	// Step 2: Collect threats from code analysis
	fmt.Println("🔍 Analyzing code for security threats...")
	codeAnalyzer := collectors.NewCodeAnalyzer(repo)
	codeThreats, err := codeAnalyzer.Collect(ctx)
	if err != nil {
		return fmt.Errorf("code analysis failed: %w", err)
	}
	fmt.Printf("✓ Found %d code-based threats\n", len(codeThreats))

	// Also collect from NVD if configured (but don't fail if unavailable)
	allThreats := codeThreats
	if cfg.Collectors.NVD.Enabled && cfg.Collectors.NVD.APIKey != "" {
		fmt.Println("🔍 Collecting additional threat intelligence from NVD...")
		nvdCollector := collectors.NewNVDCollector(cfg.Collectors.NVD.APIKey, cfg.Collectors.NVD.DaysBack)
		nvdThreats, err := nvdCollector.Collect(ctx)
		if err != nil {
			fmt.Printf("⚠️  NVD collection warning: %v\n", err)
		} else {
			allThreats = append(allThreats, nvdThreats...)
			fmt.Printf("✓ Collected %d threats from NVD\n", len(nvdThreats))
		}
	}

	// Process through pipeline
	processor := pipeline.NewProcessor(pipeline.ProcessorConfig{
		MinPriority: cfg.Pipeline.MinPriority,
		MaxAgeDays:  cfg.Pipeline.MaxAgeDays,
	})
	processedThreats, err := processor.Process(ctx, allThreats)
	if err != nil {
		return fmt.Errorf("processing failed: %w", err)
	}

	fmt.Printf("✓ Total processed threats: %d\n", len(processedThreats))
	fmt.Println()

	// Step 3: MAESTRO Analysis (if enabled)
	if enableMAESTRO {
		fmt.Println("🤖 Running MAESTRO agentic AI threat analysis...")
		maestroClassifier := maestro.NewClassifier()

		maestroInput := maestro.ClassificationInput{
			SystemDescription: fmt.Sprintf("%s %s application", repo.Language, repo.Framework),
			Technologies:      []string{repo.Language, repo.Framework},
			HasAgents:         strings.Contains(strings.ToLower(repo.Framework), "agent"),
		}

		maestroProfile := maestroClassifier.Classify(maestroInput)
		fmt.Printf("✓ MAESTRO Classification: %s\n", maestroProfile.PrimaryLayer)
		fmt.Printf("  Identified Threats: %d\n", len(maestroProfile.IdentifiedThreats))
		fmt.Println()
	}

	// Step 4: Semgrep Analysis (if enabled)
	var semgrepFindings []semgrep.Finding
	if enableSemgrep {
		fmt.Println("🔬 Running Semgrep static analysis...")
		semgrepRunner := semgrep.NewRunner("auto")
		semgrepOutput, err := semgrepRunner.Scan(ctx, repo.LocalPath)
		if err != nil {
			fmt.Printf("⚠️  Semgrep scan warning: %v\n", err)
		} else {
			semgrepFindings = semgrepOutput.Results
			filteredFindings := semgrep.FilterBySeverity(semgrepFindings, semgrep.SeverityWarning)
			fmt.Printf("✓ Semgrep found %d issues (%d WARNING+)\n", len(semgrepFindings), len(filteredFindings))

			// Map findings to STRIDE/MAESTRO
			semgrepMapper := semgrep.NewMapper()
			mappings := semgrepMapper.MapFindings(filteredFindings)
			fmt.Printf("  Mapped to %d threat categories\n", len(semgrep.GroupBySTRIDE(mappings)))
			fmt.Println()
		}
	}

	// Step 5: Map threats to code
	fmt.Println("🎯 Mapping threats to code assets...")
	threatMapper := mapper.NewThreatMapper(processedThreats)
	mappedThreats, err := threatMapper.MapThreatsToRepository(ctx, repo)
	if err != nil {
		return fmt.Errorf("threat mapping failed: %w", err)
	}

	fmt.Printf("✓ Mapped %d threats to code\n", len(mappedThreats))
	fmt.Println()

	// Step 6: MITRE ATT&CK Enrichment (if enabled)
	if enableMITRE {
		fmt.Println("🎯 Enriching with MITRE ATT&CK mappings...")
		mitreMapper := mitre.NewMapper()
		for i := range processedThreats {
			if processedThreats[i].StrideProfile != nil {
				attackMappings := mitreMapper.MapSTRIDELM(
					processedThreats[i].StrideProfile.PrimaryCategory,
					processedThreats[i].StrideProfile.ConfidenceScores[processedThreats[i].StrideProfile.PrimaryCategory],
				)
				for _, mapping := range attackMappings {
					processedThreats[i].MitreAttackIDs = append(processedThreats[i].MitreAttackIDs, mapping.TechniqueID)
				}
			}
		}
		fmt.Printf("✓ ATT&CK techniques mapped\n")
		fmt.Println()
	}

	// Step 7: Generate Data Flow Diagram (if enabled)
	if enableDataflow || enable3D {
		// Prepare base path
		basePath := outputFile
		if basePath == "" {
			basePath = "threat-model"
		}
		
		// Generate 2D diagram
		if enableDataflow {
			fmt.Println("📊 Generating 2D data flow diagram...")
			diagramPath := basePath
			if !strings.HasSuffix(diagramPath, ".html") {
				diagramPath += ".html"
			}
			
			generator := dataflow.NewGenerator()
			if err := generator.GenerateFromRepository(repo, processedThreats, diagramPath); err != nil {
				return fmt.Errorf("2D diagram generation failed: %w", err)
			}
			
			fmt.Printf("✓ 2D diagram generated: %s\n", diagramPath)
			fmt.Println()
		}
		
		// Generate 3D diagram
		if enable3D {
			fmt.Println("🌌 Generating 3D data flow visualization...")
			
			// If both flags, add -3d suffix
			diagram3DPath := basePath
			if enableDataflow {
				diagram3DPath = strings.TrimSuffix(basePath, ".html") + "-3d.html"
			} else if !strings.HasSuffix(diagram3DPath, ".html") {
				diagram3DPath += ".html"
			}
			
			// Build diagram data first
			generator := dataflow.NewGenerator()
			diagramData := generator.BuildDiagramData(repo, processedThreats)
			
			// Generate 3D visualization
			generator3D := dataflow.NewGenerator3D()
			if err := generator3D.Generate3D(diagramData, diagram3DPath); err != nil {
				return fmt.Errorf("3D diagram generation failed: %w", err)
			}
			
			fmt.Printf("✓ 3D visualization generated: %s\n", diagram3DPath)
			fmt.Println("  Open in browser to explore the stunning 3D threat model!")
			fmt.Println()
		}
	}

	// Show results
	fmt.Println("📊 Results Summary:")
	fmt.Println(strings.Repeat("-", 50))

	criticalCount := 0
	highCount := 0
	for _, mt := range mappedThreats {
		if mt.Threat.Severity == models.SeverityCritical {
			criticalCount++
		} else if mt.Threat.Severity == models.SeverityHigh {
			highCount++
		}
	}

	fmt.Printf("  🔴 Critical threats: %d\n", criticalCount)
	fmt.Printf("  🟠 High threats: %d\n", highCount)
	fmt.Printf("  📦 Total affected assets: %d\n", countAffectedAssets(mappedThreats))
	fmt.Printf("  🔄 Risky data flows: %d\n", countRiskyFlows(mappedThreats))
	if enableSemgrep {
		fmt.Printf("  🔬 Semgrep findings: %d\n", len(semgrepFindings))
	}
	fmt.Println()

	// Show top threats
	if len(mappedThreats) > 0 {
		fmt.Println("Top 5 Threats:")
		for i := 0; i < min(5, len(mappedThreats)); i++ {
			mt := mappedThreats[i]
			strideStr := ""
			if mt.Threat.StrideProfile != nil {
				strideStr = fmt.Sprintf("[%s] ", mt.Threat.StrideProfile)
			}
			fmt.Printf("  %d. [%s] %s%s (Risk: %.2f)\n",
				i+1, mt.Threat.Severity, strideStr, truncate(mt.Threat.Title, 50), mt.RiskScore)
		}
		fmt.Println()
	}

	fmt.Println("💡 Next steps:")
	if enableDataflow || enable3D {
		basePath := outputFile
		if basePath == "" {
			basePath = "threat-model.html"
		}
		fmt.Printf("   Open %s in your browser\n", basePath)
	} else {
		fmt.Println("   tito scan --repo <url> --dataflow  # Generate 2D visualization")
		fmt.Println("   tito scan --repo <url> --3d        # Generate stunning 3D visualization")
	}
	fmt.Println("   tito dashboard                     # Launch web dashboard")

	return nil
}

var dashboardCmd = &cobra.Command{
	Use:   "dashboard",
	Short: "Start the web dashboard",
	Long: `Start the TITO web dashboard to visualize threats, assets, and data flows.

The dashboard provides:
- Interactive data flow visualization
- Threat-to-code mapping
- Asset inventory
- Mitigation recommendations

Examples:
  tito dashboard
  tito dashboard --port 8080`,
	RunE: runDashboard,
}

func init() {
	dashboardCmd.Flags().IntP("port", "p", 8080, "Port to run dashboard on")
}

func runDashboard(cmd *cobra.Command, args []string) error {
	port, _ := cmd.Flags().GetInt("port")
	addr := fmt.Sprintf(":%d", port)

	fmt.Println("🚀 Starting TITO Dashboard")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Println()

	// Create dashboard server
	server, err := dashboard.NewServer(addr)
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}

	// TODO: Load scanned repositories from storage
	// For now, show empty dashboard

	fmt.Printf("📊 Dashboard URL: http://localhost%s\n", addr)
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println()

	ctx := context.Background()
	if err := server.Start(ctx); err != nil {
		return fmt.Errorf("server failed: %w", err)
	}

	return nil
}

// Helper functions

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func enabledStatus(enabled bool) string {
	if enabled {
		return "✓ Enabled"
	}
	return "✗ Disabled"
}

func getConfigPath() string {
	if cfgFile != "" {
		return cfgFile
	}
	return "None (using defaults)"
}

func countAffectedAssets(threats []mapper.MappedThreat) int {
	assetMap := make(map[string]bool)
	for _, threat := range threats {
		for _, asset := range threat.Assets {
			assetMap[asset.ID] = true
		}
	}
	return len(assetMap)
}

func countRiskyFlows(threats []mapper.MappedThreat) int {
	count := 0
	for _, threat := range threats {
		for _, flow := range threat.DataFlows {
			if flow.Sensitive {
				count++
			}
		}
	}
	return count
}

var serveCmd = &cobra.Command{
	Use:   "serve [file]",
	Short: "Serve a TITO report or diagram in the browser",
	Long: `Serve a TITO HTML report or data flow diagram via local HTTP server.

This is needed for 3D visualizations which require HTTP serving.
Automatically opens your browser.

Examples:
  tito serve threat-model.html
  tito serve threat-model-3d.html --port 8888`,
	Args: cobra.ExactArgs(1),
	RunE: runServe,
}

func init() {
	serveCmd.Flags().IntP("port", "p", 8877, "Port to serve on")
}

func runServe(cmd *cobra.Command, args []string) error {
	filePath := args[0]
	port, _ := cmd.Flags().GetInt("port")

	// Check file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Errorf("file not found: %s", filePath)
	}

	// Get absolute path and directory
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return fmt.Errorf("failed to resolve path: %w", err)
	}
	dir := filepath.Dir(absPath)
	base := filepath.Base(absPath)

	addr := fmt.Sprintf(":%d", port)
	url := fmt.Sprintf("http://localhost:%d/%s", port, base)

	// Serve the directory
	fs := http.FileServer(http.Dir(dir))
	http.Handle("/", fs)

	fmt.Println("🛡️  TITO Report Server")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("📂 Serving: %s\n", absPath)
	fmt.Printf("🌐 URL: %s\n", url)
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println()

	// Open browser
	go func() {
		time.Sleep(500 * time.Millisecond)
		openBrowser(url)
	}()

	if err := http.ListenAndServe(addr, nil); err != nil {
		return fmt.Errorf("server failed: %w", err)
	}

	return nil
}

func openBrowser(url string) {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
		args = []string{url}
	case "linux":
		cmd = "xdg-open"
		args = []string{url}
	case "windows":
		cmd = "rundll32"
		args = []string{"url.dll,FileProtocolHandler", url}
	}

	if cmd != "" {
		exec.Command(cmd, args...).Start()
	}
}
