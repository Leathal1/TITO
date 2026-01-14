package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Leathal1/TITO/pkg/collectors"
	"github.com/Leathal1/TITO/pkg/config"
	"github.com/Leathal1/TITO/pkg/dashboard"
	"github.com/Leathal1/TITO/pkg/mapper"
	"github.com/Leathal1/TITO/pkg/models"
	"github.com/Leathal1/TITO/pkg/pipeline"
	"github.com/Leathal1/TITO/pkg/reports"
	"github.com/Leathal1/TITO/pkg/scanner"
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
	Use:   "atip",
	Short: "ATIP - Advanced Threat Intelligence Platform",
	Long: `ATIP - Advanced Threat Intelligence Platform

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
		fmt.Println("  Edit this file to customize ATIP settings")
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
  atip collect --all              # Run all collectors
  atip collect --nvd              # Run only NVD collector
  atip collect --nvd --osint      # Run specific collectors`,
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
  atip report                          # Generate markdown report
  atip report -f json -o report.json   # Generate JSON report`,
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
	Short: "Show ATIP system status",
	Long:  "Display the current status of the ATIP system including configuration and collectors",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("ATIP System Status")
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
		fmt.Println("ATIP - Advanced Threat Intelligence Platform")
		fmt.Println("Version: 2.0.0 - Code Intelligence Edition")
		fmt.Println("Go implementation with STRIDE-LM framework + Repository Scanning")
	},
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a repository for threats and assets",
	Long: `Scan a code repository to discover assets, analyze data flows,
and map threats to specific code locations.

Examples:
  atip scan --repo https://github.com/user/repo
  atip scan --repo https://github.com/user/repo --branch main`,
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringP("repo", "r", "", "Repository URL to scan (required)")
	scanCmd.Flags().StringP("branch", "b", "", "Branch to scan (default: main)")
	scanCmd.MarkFlagRequired("repo")
}

func runScan(cmd *cobra.Command, args []string) error {
	repoURL, _ := cmd.Flags().GetString("repo")
	branch, _ := cmd.Flags().GetString("branch")
	if branch == "" {
		branch = "main"
	}

	fmt.Println("🔍 ATIP Repository Scanner")
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

	// Step 2: Collect threats
	fmt.Println("🔍 Collecting threat intelligence...")
	nvdCollector := collectors.NewNVDCollector(cfg.Collectors.NVD.APIKey, cfg.Collectors.NVD.DaysBack)
	threats, err := nvdCollector.Collect(ctx)
	if err != nil {
		return fmt.Errorf("threat collection failed: %w", err)
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

	fmt.Printf("✓ Collected %d threats\n", len(processedThreats))
	fmt.Println()

	// Step 3: Map threats to code
	fmt.Println("🎯 Mapping threats to code assets...")
	threatMapper := mapper.NewThreatMapper(processedThreats)
	mappedThreats, err := threatMapper.MapThreatsToRepository(ctx, repo)
	if err != nil {
		return fmt.Errorf("threat mapping failed: %w", err)
	}

	fmt.Printf("✓ Mapped %d threats to code\n", len(mappedThreats))
	fmt.Println()

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
	fmt.Println()

	// Show top threats
	if len(mappedThreats) > 0 {
		fmt.Println("Top 5 Threats:")
		for i := 0; i < min(5, len(mappedThreats)); i++ {
			mt := mappedThreats[i]
			fmt.Printf("  %d. [%s] %s (Risk: %.2f)\n",
				i+1, mt.Threat.Severity, truncate(mt.Threat.Title, 60), mt.RiskScore)
			if len(mt.Assets) > 0 {
				fmt.Printf("     Assets: %d | Mitigations: %d\n", len(mt.Assets), len(mt.Mitigations))
			}
		}
		fmt.Println()
	}

	fmt.Println("💡 Next step: Launch dashboard to visualize")
	fmt.Println("   atip dashboard")

	return nil
}

var dashboardCmd = &cobra.Command{
	Use:   "dashboard",
	Short: "Start the web dashboard",
	Long: `Start the ATIP web dashboard to visualize threats, assets, and data flows.

The dashboard provides:
- Interactive data flow visualization
- Threat-to-code mapping
- Asset inventory
- Mitigation recommendations

Examples:
  atip dashboard
  atip dashboard --port 8080`,
	RunE: runDashboard,
}

func init() {
	dashboardCmd.Flags().IntP("port", "p", 8080, "Port to run dashboard on")
}

func runDashboard(cmd *cobra.Command, args []string) error {
	port, _ := cmd.Flags().GetInt("port")
	addr := fmt.Sprintf(":%d", port)

	fmt.Println("🚀 Starting ATIP Dashboard")
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
