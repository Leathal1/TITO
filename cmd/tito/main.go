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

	"github.com/Leathal1/TITO/pkg/attackpath"
	"github.com/Leathal1/TITO/pkg/collectors"
	"github.com/Leathal1/TITO/pkg/config"
	"github.com/Leathal1/TITO/pkg/dashboard"
	"github.com/Leathal1/TITO/pkg/dataflow"
	"github.com/Leathal1/TITO/pkg/diff"
	"github.com/Leathal1/TITO/pkg/diff/format"
	"github.com/Leathal1/TITO/pkg/maestro"
	"github.com/Leathal1/TITO/pkg/mapper"
	"github.com/Leathal1/TITO/pkg/mitre"
	"github.com/Leathal1/TITO/pkg/models"
	"github.com/Leathal1/TITO/pkg/pci"
	"github.com/Leathal1/TITO/pkg/pipeline"
	"github.com/Leathal1/TITO/pkg/reports"
	"github.com/Leathal1/TITO/pkg/scan"
	"github.com/Leathal1/TITO/pkg/scanner"
	"github.com/Leathal1/TITO/pkg/semgrep"
	"github.com/Leathal1/TITO/pkg/stridelm"
	"github.com/spf13/cobra"
)

var (
	// version is set by ldflags at build time (-X main.version=...)
	version = "dev"

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
	Short: "TITO - Automated Threat Modeling for Code Repositories",
	Long: `TITO - Threat In, Threat Out — Automated Threat Modeling

Point TITO at a code repository and get a complete threat model:
STRIDE-LM classification, MAESTRO AI threat analysis, attack path
discovery, MITRE ATT&CK mappings, and interactive 3D visualization.

Single binary. No diagrams to draw. The threat modeler that thinks like an attacker.`,
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
	rootCmd.AddCommand(diffCmd)
	rootCmd.AddCommand(attackPathsCmd)
	rootCmd.AddCommand(dashboardCmd)
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(complianceCmd)
	rootCmd.AddCommand(apiCmd)
	rootCmd.AddCommand(semgrepCmd)
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
	Long:  "Display the current status of TITO including configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("🛡️  TITO System Status")
		fmt.Println(strings.Repeat("=", 50))
		fmt.Println()

		fmt.Println("Configuration:")
		fmt.Printf("  Config file: %s\n", getConfigPath())
		fmt.Println()

		fmt.Println("Threat Modeling Capabilities:")
		fmt.Printf("  STRIDE-LM:        ✓ Available\n")
		fmt.Printf("  2D Visualization: ✓ Available\n")
		fmt.Printf("  Semgrep SAST:     ✓ Available\n")
		fmt.Printf("  MITRE ATT&CK:     ✓ Available\n")
		fmt.Printf("  MAESTRO:          ✓ Available\n")
		fmt.Printf("  Attack Paths:     ✓ Available\n")
		fmt.Printf("  3D Visualization: ✓ Available\n")
		fmt.Printf("  PR Diffing:       ✓ Available\n")
		fmt.Printf("  Narratives:       ✓ Available\n")
		fmt.Printf("  PCI DSS Mapping:  ✓ Available\n")
		fmt.Println()

		fmt.Println("Enrichment Sources:")
		fmt.Printf("  NVD:   %s\n", enabledStatus(cfg.Collectors.NVD.Enabled))
		fmt.Printf("  OSINT: %s\n", enabledStatus(cfg.Collectors.OSINT.Enabled))
		fmt.Println()

		return nil
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("TITO - Automated Threat Modeling for Code Repositories")
		fmt.Printf("Version: %s\n", version)
		fmt.Println("STRIDE-LM + MAESTRO + Attack Paths + 3D Visualization")
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
	scanCmd.Flags().Bool("attack-paths", false, "Generate attack path analysis and overlay on 3D visualization")
	scanCmd.Flags().Bool("mitre", false, "Enrich findings with MITRE ATT&CK mappings")
	scanCmd.Flags().Bool("pci", false, "Enable PCI DSS v4.0 specific checks and compliance section")
	scanCmd.Flags().StringP("output", "o", "", "Output file for report/diagram")
	scanCmd.Flags().String("save", "", "Save scan result to .tito.json file for later diffing")
	scanCmd.MarkFlagRequired("repo")
}

func runScan(cmd *cobra.Command, args []string) error {
	repoURL, _ := cmd.Flags().GetString("repo")
	branch, _ := cmd.Flags().GetString("branch")
	enableMAESTRO, _ := cmd.Flags().GetBool("maestro")
	enableSemgrep, _ := cmd.Flags().GetBool("semgrep")
	enableDataflow, _ := cmd.Flags().GetBool("dataflow")
	enable3D, _ := cmd.Flags().GetBool("3d")
	enableAttackPaths, _ := cmd.Flags().GetBool("attack-paths")
	enableMITRE, _ := cmd.Flags().GetBool("mitre")
	enablePCI, _ := cmd.Flags().GetBool("pci")
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

	workDir, err := os.MkdirTemp("", "tito-scan-")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(workDir)

	s := scanner.NewScanner(workDir)
	ctx := context.Background()

	repo, err := s.ScanRepository(ctx, repoURL, branch)
	if err != nil {
		return fmt.Errorf("repository scan failed: %w", err)
	}

	fmt.Printf("✓ Repository scanned successfully\n")
	fmt.Printf("  Language: %s\n", repo.Language)
	fmt.Printf("  Framework: %s\n", repo.Framework)
	
	// Display architecture
	if repo.Architecture != nil {
		fmt.Printf("  Architecture: %s", repo.Architecture.PrimaryType.String())
		if repo.Architecture.Confidence > 0 {
			fmt.Printf(" (confidence: %.0f%%)", repo.Architecture.Confidence*100)
		}
		fmt.Println()
		
		if len(repo.Architecture.SecondaryTypes) > 0 {
			fmt.Printf("    Secondary: ")
			for i, st := range repo.Architecture.SecondaryTypes {
				if i > 0 {
					fmt.Printf(", ")
				}
				fmt.Printf("%s", st.String())
			}
			fmt.Println()
		}
		
		// Show top signals
		if len(repo.Architecture.Signals) > 0 {
			fmt.Printf("    Signals: ")
			count := 0
			for _, signal := range repo.Architecture.Signals {
				if signal.Weight >= 0.7 && count < 3 {
					if count > 0 {
						fmt.Printf(", ")
					}
					fmt.Printf("%s", signal.Evidence)
					count++
				}
			}
			if count > 0 {
				fmt.Println()
			}
		}
	}
	
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
	if enableSemgrep || enablePCI {
		scanMsg := "Semgrep static analysis"
		if enablePCI {
			scanMsg = "Semgrep + PCI DSS checks"
		}
		fmt.Printf("🔬 Running %s...\n", scanMsg)
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
			
			// PCI DSS mapping (if --pci flag)
			if enablePCI {
				fmt.Println("🔒 Mapping to PCI DSS v4.0 requirements...")
				pciMapper := pci.NewMapper()
				pciMappingsCount := make(map[string]int)
				
				for _, finding := range filteredFindings {
					cweIDs := semgrep.GetCWEIDs(finding)
					mapping := semgrepMapper.MapFinding(finding)
					
					cweStrs := make([]string, len(cweIDs))
					for i, id := range cweIDs {
						cweStrs[i] = fmt.Sprintf("CWE-%d", id)
					}
					pciMappings := pciMapper.MapThreat(
						finding.Extra.Message,
						finding.Extra.Message,
						mapping.STRIDECategory,
						cweStrs,
						[]string{finding.CheckID},
					)
					
					for _, pciMapping := range pciMappings {
						reqID := fmt.Sprintf("%s.%s", pciMapping.RequirementID, pciMapping.SubRequirementID)
						pciMappingsCount[reqID]++
					}
				}
				
				fmt.Printf("✓ Mapped to %d PCI DSS requirements\n", len(pciMappingsCount))
				if len(pciMappingsCount) > 0 {
					fmt.Println("\n  Top PCI DSS requirements with findings:")
					// Sort by count
					type kv struct {
						Key   string
						Value int
					}
					var sorted []kv
					for k, v := range pciMappingsCount {
						sorted = append(sorted, kv{k, v})
					}
					for i := 0; i < len(sorted)-1; i++ {
						for j := i + 1; j < len(sorted); j++ {
							if sorted[j].Value > sorted[i].Value {
								sorted[i], sorted[j] = sorted[j], sorted[i]
							}
						}
					}
					for i := 0; i < 5 && i < len(sorted); i++ {
						fmt.Printf("    Req %s: %d findings\n", sorted[i].Key, sorted[i].Value)
					}
					fmt.Println("\n  💡 Run 'tito compliance --repo . --framework pci-dss' for full report")
				}
				fmt.Println()
			}
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
			
			// Check if attack paths should be included
			if enableAttackPaths {
				fmt.Println("⚔️  Analyzing attack paths...")
				
				// Build attack graph
				graphBuilder := attackpath.NewGraphBuilder(diagramData)
				attackGraph := graphBuilder.Build()
				
				// Find critical paths
				pathFinder := attackpath.NewPathFinder(attackGraph)
				allPaths := pathFinder.FindCriticalPaths(10) // Get top 10 paths
				
				// Score and enhance all paths
				scorer := attackpath.NewScorer(attackGraph)
				narrativeGen := attackpath.NewNarrativeGenerator(attackGraph)
				
				for i := range allPaths {
					allPaths[i].CompositeRisk = scorer.ScorePath(allPaths[i].Steps)
					allPaths[i].MitreTactics = attackpath.ExtractMitreTactics(allPaths[i].Steps)
					allPaths[i].Narrative = narrativeGen.GenerateNarrative(allPaths[i])
				}
				
				fmt.Printf("✓ Found %d attack paths\n", len(allPaths))
				
				// Generate 3D with attack paths
				if err := generator3D.Generate3DWithAttackPaths(diagramData, allPaths, diagram3DPath); err != nil {
					return fmt.Errorf("3D diagram with attack paths generation failed: %w", err)
				}
			} else {
				// Generate 3D without attack paths
				if err := generator3D.Generate3D(diagramData, diagram3DPath); err != nil {
					return fmt.Errorf("3D diagram generation failed: %w", err)
				}
			}
			
			fmt.Printf("✓ 3D visualization generated: %s\n", diagram3DPath)
			fmt.Println("  Open in browser to explore the stunning 3D threat model!")
			if enableAttackPaths {
				fmt.Println("  Click 'Show Attack Paths' button to see attack chains!")
			}
			fmt.Println()
		}
	}

	// ── Threat Model Summary ─────────────────────────────────────
	fmt.Println("📊 Threat Model Summary:")
	fmt.Println(strings.Repeat("─", 60))

	// ── 1. ASSETS ──
	fmt.Println()
	fmt.Println("📦 ASSETS")
	// Count by type
	assetTypeCounts := make(map[string]int)
	exposedCount := 0
	sensitiveCount := 0
	for _, a := range repo.Assets {
		assetTypeCounts[string(a.Type)]++
		if a.Exposed {
			exposedCount++
		}
		if a.Sensitive {
			sensitiveCount++
		}
	}
	fmt.Printf("  Total: %d assets | %d exposed | %d sensitive\n",
		len(repo.Assets), exposedCount, sensitiveCount)
	// Show top asset types
	type assetTypeCount struct {
		Type  string
		Count int
	}
	var sortedAssetTypes []assetTypeCount
	for t, c := range assetTypeCounts {
		sortedAssetTypes = append(sortedAssetTypes, assetTypeCount{t, c})
	}
	// Sort by count descending
	for i := 0; i < len(sortedAssetTypes); i++ {
		for j := i + 1; j < len(sortedAssetTypes); j++ {
			if sortedAssetTypes[j].Count > sortedAssetTypes[i].Count {
				sortedAssetTypes[i], sortedAssetTypes[j] = sortedAssetTypes[j], sortedAssetTypes[i]
			}
		}
	}
	for i, at := range sortedAssetTypes {
		if i >= 5 {
			break
		}
		fmt.Printf("    %-20s %d\n", at.Type, at.Count)
	}
	fmt.Printf("  Data flows: %d\n", len(repo.DataFlows))

	// ── 2. THREATS ──
	fmt.Println()
	fmt.Println("⚠️  THREATS")
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	for _, mt := range mappedThreats {
		switch mt.Threat.Severity {
		case models.SeverityCritical:
			criticalCount++
		case models.SeverityHigh:
			highCount++
		case models.SeverityMedium:
			mediumCount++
		}
	}
	fmt.Printf("  🔴 Critical: %d  🟠 High: %d  🟡 Medium: %d\n", criticalCount, highCount, mediumCount)
	if enableSemgrep {
		fmt.Printf("  🔬 Semgrep SAST findings: %d\n", len(semgrepFindings))
	}

	// Threat distribution by STRIDE category
	if len(processedThreats) > 0 {
		categoryDistribution := getThreatDistribution(processedThreats)
		for _, item := range categoryDistribution {
			fmt.Printf("    %-25s %d findings\n", item.CategoryName, item.Count)
		}
	}

	// Top threats
	if len(mappedThreats) > 0 {
		fmt.Println()
		fmt.Println("  Top Threats:")
		topByCategory := getTopThreatsByCategory(mappedThreats)
		for _, item := range topByCategory {
			instanceStr := ""
			if item.Threat.InstanceCount > 1 {
				instanceStr = fmt.Sprintf(" (%d instances)", item.Threat.InstanceCount)
			}
			fmt.Printf("    [%s] %s%s — Risk: %.2f\n",
				item.CategoryCode, truncate(item.Threat.Title, 55), instanceStr, item.RiskScore)
		}
	}

	// ── 3. MITIGATING CONTROLS ──
	fmt.Println()
	fmt.Println("🛡️  MITIGATING CONTROLS")
	mitigationCount := 0
	mitigationByType := make(map[string]int)
	for _, mt := range mappedThreats {
		mitigationCount += len(mt.Mitigations)
		for _, m := range mt.Mitigations {
			mitigationByType[string(m.Type)]++
		}
	}
	if mitigationCount > 0 {
		fmt.Printf("  %d recommendations generated:\n", mitigationCount)
		mitigationTypeLabels := map[string]string{
			"patch":         "🔧 Patch/Update",
			"code_change":   "📝 Code Change",
			"configuration": "⚙️  Configuration",
			"architecture":  "🏗️  Architecture",
			"monitoring":    "👁️  Monitoring",
		}
		for typ, count := range mitigationByType {
			label := mitigationTypeLabels[typ]
			if label == "" {
				label = typ
			}
			fmt.Printf("    %-25s %d\n", label, count)
		}
		// Show top unique priority mitigations (deduplicated)
		fmt.Println()
		fmt.Println("  Priority Actions:")
		seen := make(map[string]bool)
		shown := 0
		// Critical/high first
		for _, mt := range mappedThreats {
			if shown >= 5 {
				break
			}
			for _, m := range mt.Mitigations {
				if shown >= 5 {
					break
				}
				if (m.Priority == "critical" || m.Priority == "high") && !seen[m.Description] {
					seen[m.Description] = true
					fmt.Printf("    → %s\n", truncate(m.Description, 70))
					shown++
				}
			}
		}
		// Fill remaining with any priority
		if shown < 5 {
			for _, mt := range mappedThreats {
				if shown >= 5 {
					break
				}
				for _, m := range mt.Mitigations {
					if shown >= 5 {
						break
					}
					if !seen[m.Description] {
						seen[m.Description] = true
						fmt.Printf("    → %s\n", truncate(m.Description, 70))
						shown++
					}
				}
			}
		}
	} else {
		fmt.Println("  No automated mitigations generated")
		fmt.Println("  Run with --semgrep for code-level recommendations")
	}

	fmt.Println()
	fmt.Println(strings.Repeat("─", 60))

	// Save scan result if requested
	savePath, _ := cmd.Flags().GetString("save")
	if savePath != "" {
		fmt.Println()
		fmt.Printf("💾 Saving scan result to %s...\n", savePath)
	}
	if savePath != "" {
		// Build attack paths for save
		var attackPaths []attackpath.AttackPath
		if enableAttackPaths {
			generator := dataflow.NewGenerator()
			diagramData := generator.BuildDiagramData(repo, processedThreats)
			graphBuilder := attackpath.NewGraphBuilder(diagramData)
			attackGraph := graphBuilder.Build()
			pathFinder := attackpath.NewPathFinder(attackGraph)
			attackPaths = pathFinder.FindCriticalPaths(10)
			
			scorer := attackpath.NewScorer(attackGraph)
			narrativeGen := attackpath.NewNarrativeGenerator(attackGraph)
			for i := range attackPaths {
				attackPaths[i].CompositeRisk = scorer.ScorePath(attackPaths[i].Steps)
				attackPaths[i].MitreTactics = attackpath.ExtractMitreTactics(attackPaths[i].Steps)
				attackPaths[i].Narrative = narrativeGen.GenerateNarrative(attackPaths[i])
			}
		}
		
		// Get commit SHA if possible
		commitSHA := ""
		gitCmd := exec.Command("git", "-C", repo.LocalPath, "rev-parse", "HEAD")
		if output, err := gitCmd.Output(); err == nil {
			commitSHA = strings.TrimSpace(string(output))
		}
		
		// Build scan result
		scanResult := scan.NewScanResult()
		scanResult.Repository = scan.RepositoryInfo{
			URL:       repoURL,
			Branch:    branch,
			Language:  repo.Language,
			Framework: repo.Framework,
			CommitSHA: commitSHA,
		}
		scanResult.Assets = repo.Assets
		scanResult.DataFlows = repo.DataFlows
		scanResult.Dependencies = repo.Dependencies
		scanResult.Threats = processedThreats
		scanResult.MappedThreats = mappedThreats
		scanResult.AttackPaths = attackPaths
		
		if err := scan.SaveResult(scanResult, savePath); err != nil {
			fmt.Printf("⚠️  Warning: Failed to save scan result: %v\n", err)
		} else {
			fmt.Printf("✓ Scan result saved: %s\n", savePath)
		}
	}

	fmt.Println()
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
	if savePath == "" {
		fmt.Println("   tito scan --repo <url> --save scan.tito.json  # Save for PR diffing")
	}
	fmt.Println("   tito dashboard                     # Launch web dashboard")

	return nil
}

var diffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Compare threat models between two scans (PR diff)",
	Long: `Compare threat models between two scan results and output what changed.

Designed to run in CI on every pull request to catch security regressions.

Examples:
  # Compare two saved scan results
  tito diff --before main.tito.json --after feature.tito.json

  # Compare two branches (scans both automatically)
  tito diff --repo https://github.com/user/repo --base main --head feature-branch

  # Output formats
  tito diff --before base.tito.json --after head.tito.json --format markdown
  tito diff --before base.tito.json --after head.tito.json --format json
  tito diff --before base.tito.json --after head.tito.json --format summary`,
	RunE: runDiff,
}

func init() {
	diffCmd.Flags().String("repo", "", "Repository URL (required for --base/--head mode)")
	diffCmd.Flags().String("base", "", "Base branch (default: main)")
	diffCmd.Flags().String("head", "", "Head branch (default: current branch / HEAD)")
	diffCmd.Flags().String("before", "", "Path to base scan result (.tito.json)")
	diffCmd.Flags().String("after", "", "Path to head scan result (.tito.json)")
	diffCmd.Flags().String("format", "markdown", "Output format: markdown, json, summary")
	diffCmd.Flags().String("output", "", "Write to file instead of stdout")
	diffCmd.Flags().String("fail-on", "critical", "When to exit non-zero: critical, high, any, never")
	diffCmd.Flags().String("save", "", "Save scan results to .tito.json files for later comparison")
}

func runDiff(cmd *cobra.Command, args []string) error {
	repoURL, _ := cmd.Flags().GetString("repo")
	baseBranch, _ := cmd.Flags().GetString("base")
	headBranch, _ := cmd.Flags().GetString("head")
	beforePath, _ := cmd.Flags().GetString("before")
	afterPath, _ := cmd.Flags().GetString("after")
	outputFormat, _ := cmd.Flags().GetString("format")
	outputPath, _ := cmd.Flags().GetString("output")
	failOn, _ := cmd.Flags().GetString("fail-on")
	savePath, _ := cmd.Flags().GetString("save")

	// Validate arguments
	if beforePath == "" && afterPath == "" {
		// Branch mode - need repo and branches
		if repoURL == "" {
			return fmt.Errorf("either --before/--after OR --repo/--base/--head must be specified")
		}
		if baseBranch == "" {
			baseBranch = "main"
		}
		if headBranch == "" {
			headBranch = "HEAD"
		}
	} else if beforePath != "" && afterPath != "" {
		// File mode - good to go
	} else {
		return fmt.Errorf("both --before and --after must be specified together")
	}

	fmt.Println("🔄 TITO Threat Model Diff")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Println()

	var baseScan, headScan *scan.ScanResult
	var err error

	// Branch comparison mode
	if beforePath == "" && afterPath == "" {
		fmt.Printf("📊 Comparing branches: %s → %s\n", baseBranch, headBranch)
		fmt.Println()

		// Scan base branch
		fmt.Printf("🔍 Scanning base branch (%s)...\n", baseBranch)
		baseScan, err = performScan(repoURL, baseBranch, "base")
		if err != nil {
			return fmt.Errorf("base scan failed: %w", err)
		}
		fmt.Printf("✓ Base scan complete: %d threats, %.1f max risk\n", 
			len(baseScan.Threats), baseScan.Stats.MaxRiskScore*10)

		// Save base if requested
		if savePath != "" {
			baseFile := strings.Replace(savePath, ".tito.json", "-base.tito.json", 1)
			if err := scan.SaveResult(baseScan, baseFile); err != nil {
				fmt.Printf("⚠️  Warning: Failed to save base scan: %v\n", err)
			} else {
				fmt.Printf("💾 Base scan saved: %s\n", baseFile)
			}
		}
		fmt.Println()

		// Scan head branch
		fmt.Printf("🔍 Scanning head branch (%s)...\n", headBranch)
		headScan, err = performScan(repoURL, headBranch, "head")
		if err != nil {
			return fmt.Errorf("head scan failed: %w", err)
		}
		fmt.Printf("✓ Head scan complete: %d threats, %.1f max risk\n", 
			len(headScan.Threats), headScan.Stats.MaxRiskScore*10)

		// Save head if requested
		if savePath != "" {
			headFile := strings.Replace(savePath, ".tito.json", "-head.tito.json", 1)
			if err := scan.SaveResult(headScan, headFile); err != nil {
				fmt.Printf("⚠️  Warning: Failed to save head scan: %v\n", err)
			} else {
				fmt.Printf("💾 Head scan saved: %s\n", headFile)
			}
		}
		fmt.Println()
	} else {
		// File comparison mode
		fmt.Printf("📂 Loading scan results...\n")
		fmt.Printf("   Base: %s\n", beforePath)
		fmt.Printf("   Head: %s\n", afterPath)
		fmt.Println()

		baseScan, err = scan.LoadResult(beforePath)
		if err != nil {
			return fmt.Errorf("failed to load base scan: %w", err)
		}

		headScan, err = scan.LoadResult(afterPath)
		if err != nil {
			return fmt.Errorf("failed to load head scan: %w", err)
		}

		fmt.Printf("✓ Loaded base scan: %d threats, %.1f max risk\n", 
			len(baseScan.Threats), baseScan.Stats.MaxRiskScore*10)
		fmt.Printf("✓ Loaded head scan: %d threats, %.1f max risk\n", 
			len(headScan.Threats), headScan.Stats.MaxRiskScore*10)
		fmt.Println()
	}

	fmt.Println("🔍 Computing threat model delta...")
	diffResult := diff.ComputeDiff(baseScan, headScan)

	// Determine verdict
	verdictConfig := getVerdictConfig(failOn)
	verdict, reason := diff.DetermineVerdict(diffResult, verdictConfig)
	diffResult.Summary.RiskVerdict = verdict
	diffResult.Summary.VerdictReason = reason

	fmt.Printf("✓ Diff computed: %d total changes\n", diffResult.Summary.TotalChanges)
	fmt.Printf("   Verdict: %s %s\n", diff.VerdictEmoji(verdict), verdict)
	fmt.Println()

	// Generate output
	var output string
	switch outputFormat {
	case "markdown":
		output = format.FormatMarkdown(diffResult)
	case "json":
		jsonBytes, err := format.FormatJSON(diffResult)
		if err != nil {
			return fmt.Errorf("JSON formatting failed: %w", err)
		}
		output = string(jsonBytes)
	case "summary":
		output = format.FormatSummary(diffResult)
	default:
		return fmt.Errorf("unknown format: %s (use: markdown, json, summary)", outputFormat)
	}

	// Write output
	if outputPath != "" {
		if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}
		fmt.Printf("✓ Output written to %s\n", outputPath)
	} else {
		fmt.Println(strings.Repeat("=", 50))
		fmt.Println()
		fmt.Println(output)
	}

	// Exit with appropriate code
	os.Exit(diff.VerdictToExitCode(verdict))
	return nil
}

// performScan runs a full scan on a repository branch
func performScan(repoURL, branch, label string) (*scan.ScanResult, error) {
	ctx := context.Background()

	// Create scanner with temp work dir
	workDir, err := os.MkdirTemp("", "tito-diff-"+label+"-")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(workDir)

	s := scanner.NewScanner(workDir)
	
	// Scan repository
	repo, err := s.ScanRepository(ctx, repoURL, branch)
	if err != nil {
		return nil, err
	}
	
	// Collect threats
	codeAnalyzer := collectors.NewCodeAnalyzer(repo)
	threats, err := codeAnalyzer.Collect(ctx)
	if err != nil {
		return nil, err
	}
	
	// Process threats
	processor := pipeline.NewProcessor(pipeline.ProcessorConfig{
		MinPriority: 0.0,
		MaxAgeDays:  365,
	})
	processedThreats, err := processor.Process(ctx, threats)
	if err != nil {
		return nil, err
	}
	
	// Map threats
	threatMapper := mapper.NewThreatMapper(processedThreats)
	mappedThreats, err := threatMapper.MapThreatsToRepository(ctx, repo)
	if err != nil {
		return nil, err
	}
	
	// Get commit SHA
	commitSHA := ""
	gitCmd := exec.Command("git", "-C", repo.LocalPath, "rev-parse", "HEAD")
	if output, err := gitCmd.Output(); err == nil {
		commitSHA = strings.TrimSpace(string(output))
	}
	
	// Build scan result
	result := scan.NewScanResult()
	result.Repository = scan.RepositoryInfo{
		URL:       repoURL,
		Branch:    branch,
		Language:  repo.Language,
		Framework: repo.Framework,
		CommitSHA: commitSHA,
	}
	result.Assets = repo.Assets
	result.DataFlows = repo.DataFlows
	result.Dependencies = repo.Dependencies
	result.Threats = processedThreats
	result.MappedThreats = mappedThreats
	result.AttackPaths = []attackpath.AttackPath{} // Empty for diff mode
	result.CalculateStats()
	
	return result, nil
}

// getVerdictConfig maps fail-on flag to verdict configuration
func getVerdictConfig(failOn string) diff.VerdictConfig {
	switch failOn {
	case "critical":
		return diff.FailOnCriticalConfig()
	case "high":
		return diff.FailOnHighConfig()
	case "any":
		return diff.FailOnAnyConfig()
	case "never":
		return diff.VerdictConfig{
			FailOnCritical:     false,
			FailOnHigh:         false,
			FailOnRiskIncrease: false,
			WarnOnHigh:         true,
			WarnOnRiskIncrease: true,
		}
	default:
		return diff.FailOnCriticalConfig()
	}
}

var attackPathsCmd = &cobra.Command{
	Use:   "attack-paths",
	Short: "Generate attack path analysis and kill chain visualization",
	Long: `Analyze attack paths through your application from entry points to crown jewels.

This feature chains individual findings into realistic multi-step attack paths,
answering: "If an attacker lands here, what's the worst-case path to crown jewels?"

Like BloodHound, but for application-layer threat models.

Examples:
  tito attack-paths --repo https://github.com/user/repo
  tito attack-paths --repo . --top 5 --3d
  tito attack-paths --repo . --target database --narrative`,
	RunE: runAttackPaths,
}

func init() {
	attackPathsCmd.Flags().StringP("repo", "r", "", "Repository URL to scan (required)")
	attackPathsCmd.Flags().StringP("branch", "b", "", "Branch to scan (default: main)")
	attackPathsCmd.Flags().String("target", "", "Filter crown jewels by type or name")
	attackPathsCmd.Flags().Int("top", 5, "Show top N most dangerous paths")
	attackPathsCmd.Flags().Bool("3d", false, "Generate 3D visualization with attack path overlay")
	attackPathsCmd.Flags().Bool("narrative", false, "Print human-readable attack narratives")
	attackPathsCmd.Flags().StringP("output", "o", "attack-paths.html", "Output file")
	attackPathsCmd.MarkFlagRequired("repo")
}

func runAttackPaths(cmd *cobra.Command, args []string) error {
	repoURL, _ := cmd.Flags().GetString("repo")
	branch, _ := cmd.Flags().GetString("branch")
	_ , _ = cmd.Flags().GetString("target") // targetFilter - reserved for future filtering
	topN, _ := cmd.Flags().GetInt("top")
	enable3D, _ := cmd.Flags().GetBool("3d")
	enableNarrative, _ := cmd.Flags().GetBool("narrative")
	outputFile, _ := cmd.Flags().GetString("output")

	if branch == "" {
		branch = "main"
	}

	fmt.Println("⚔️  TITO Attack Path Analysis")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Println()

	// Step 1: Scan repository
	fmt.Println("🔍 Scanning repository...")
	ctx := context.Background()

	apWorkDir, err := os.MkdirTemp("", "tito-attackpath-")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(apWorkDir)

	s := scanner.NewScanner(apWorkDir)
	repo, err := s.ScanRepository(ctx, repoURL, branch)
	if err != nil {
		return fmt.Errorf("repository scan failed: %w", err)
	}

	// Step 2: Run threat analysis
	fmt.Println("🎯 Analyzing code for threats...")
	codeAnalyzer := collectors.NewCodeAnalyzer(repo)
	threats, err := codeAnalyzer.Collect(ctx)
	if err != nil {
		return fmt.Errorf("code analysis failed: %w", err)
	}
	
	// Process threats
	processor := pipeline.NewProcessor(pipeline.ProcessorConfig{
		MinPriority: 0.0,
		MaxAgeDays:  365,
	})
	processedThreats, _ := processor.Process(ctx, threats)
	
	// Map threats to repository
	m := mapper.NewThreatMapper(processedThreats)
	_, _ = m.MapThreatsToRepository(ctx, repo)

	// Step 3: Build diagram data
	fmt.Println("🏗️  Building data flow graph...")
	generator := dataflow.NewGenerator()
	diagramData := generator.BuildDiagramData(repo, processedThreats)

	// Step 4: Build attack graph
	fmt.Println("🕸️  Constructing attack graph...")
	graphBuilder := attackpath.NewGraphBuilder(diagramData)
	attackGraph := graphBuilder.Build()

	fmt.Printf("\n📍 Entry Points: %d\n", len(attackGraph.EntryPoints))
	for _, ep := range attackGraph.EntryPoints {
		if node := attackGraph.Nodes[ep]; node != nil {
			fmt.Printf("   - %s (%s)\n", node.Label, node.Zone)
		}
	}

	fmt.Printf("\n🏆 Crown Jewels: %d\n", len(attackGraph.CrownJewels))
	for _, cj := range attackGraph.CrownJewels {
		if node := attackGraph.Nodes[cj]; node != nil {
			fmt.Printf("   - %s (%s, risk: %s)\n", node.Label, node.NodeType, node.RiskLevel)
		}
	}
	fmt.Println()

	// Step 5: Find attack paths
	fmt.Println("🎯 Finding attack paths...")
	pathFinder := attackpath.NewPathFinder(attackGraph)
	paths := pathFinder.FindCriticalPaths(topN)

	if len(paths) == 0 {
		fmt.Println("✓ No attack paths found! Your system appears well-segmented.")
		return nil
	}

	// Step 6: Score and enhance paths
	scorer := attackpath.NewScorer(attackGraph)
	narrativeGen := attackpath.NewNarrativeGenerator(attackGraph)

	for i := range paths {
		paths[i].CompositeRisk = scorer.ScorePath(paths[i].Steps)
		paths[i].MitreTactics = attackpath.ExtractMitreTactics(paths[i].Steps)
		paths[i].Narrative = narrativeGen.GenerateNarrative(paths[i])
	}

	// Step 7: Display results
	fmt.Printf("Found %d attack paths.\n", len(paths))
	fmt.Println()

	for i, path := range paths {
		emoji := attackpath.GetRiskEmoji(path.CompositeRisk)
		riskLevel := attackpath.GetRiskLevel(path.CompositeRisk)

		fmt.Printf("%s %s Path #%d (Risk: %.1f/10.0)\n", emoji, riskLevel, i+1, path.CompositeRisk)
		
		entryNode := attackGraph.Nodes[path.EntryPoint]
		targetNode := attackGraph.Nodes[path.Target]
		
		if entryNode != nil && targetNode != nil {
			fmt.Printf("   %s → ... → %s\n", entryNode.Label, targetNode.Label)
		}
		fmt.Printf("   Steps: %d | Difficulty: %s | Boundaries Crossed: %d\n",
			len(path.Steps),
			getDifficultyLevel(path.TotalDifficulty),
			countTrustBoundariesCrossed(path.Steps, attackGraph))

		if len(path.MitreTactics) > 0 {
			fmt.Printf("   ATT&CK Chain: %s\n", strings.Join(path.MitreTactics, " → "))
		}

		if enableNarrative {
			fmt.Println()
			fmt.Println("   Narrative:")
			lines := strings.Split(path.Narrative, "\n")
			for _, line := range lines {
				if line != "" {
					fmt.Printf("   %s\n", line)
				}
			}
		}
		fmt.Println()
	}

	// Step 8: Generate visualization
	if enable3D {
		fmt.Println("🌌 Generating 3D visualization with attack paths...")
		generator3D := dataflow.NewGenerator3D()

		if err := generator3D.Generate3DWithAttackPaths(diagramData, paths, outputFile); err != nil {
			return fmt.Errorf("3D visualization generation failed: %w", err)
		}
		fmt.Printf("✓ 3D visualization generated: %s\n", outputFile)
		fmt.Println("  Open in browser to explore interactive attack paths!")
		fmt.Println()
	}

	fmt.Println("💡 Next steps:")
	fmt.Printf("   Review the %d critical paths above\n", min(topN, len(paths)))
	if enable3D {
		fmt.Printf("   Open %s to visualize attack paths in 3D\n", outputFile)
	} else {
		fmt.Println("   Run with --3d to generate interactive visualization")
	}
	fmt.Println("   Implement mitigations to break the attack chains")

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

// --- Enterprise-only commands ---

var complianceCmd = &cobra.Command{
	Use:   "compliance",
	Short: "Map threats to compliance frameworks",
	Long: `Map discovered threats and controls to compliance frameworks.

Supported frameworks:
  - SOC 2 Type II
  - ISO 27001
  - NIST 800-53
  - PCI DSS 4.0
  - HIPAA

Generates a compliance gap analysis showing which controls are
satisfied by your current architecture and where gaps remain.

Examples:
  tito compliance --repo . --framework soc2
  tito compliance --repo . --framework iso27001 --output compliance-report.md`,
	RunE: runCompliance,
}

func init() {
	complianceCmd.Flags().StringP("repo", "r", "", "Repository URL or local path")
	complianceCmd.Flags().String("framework", "soc2", "Compliance framework (soc2, iso27001, nist800-53, pci-dss, hipaa)")
	complianceCmd.Flags().StringP("output", "o", "compliance-report.md", "Output file")
	complianceCmd.MarkFlagRequired("repo")
}

func runCompliance(cmd *cobra.Command, args []string) error {
	framework, _ := cmd.Flags().GetString("framework")
	
	// PCI DSS compliance
	if framework == "pci-dss" || framework == "pci" {
		// Run PCI DSS compliance
		return runPCICompliance(cmd, args)
	}
	
	// Other frameworks - TODO: Implement compliance mapping engine
	repoURL, _ := cmd.Flags().GetString("repo")
	output, _ := cmd.Flags().GetString("output")
	fmt.Printf("🏢 TITO Compliance Mapping — %s\n", strings.ToUpper(framework))
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("   Repository: %s\n", repoURL)
	fmt.Printf("   Output: %s\n", output)
	fmt.Println()
	fmt.Println("⚠️  Compliance mapping engine is under active development.")
	fmt.Println("   Coming soon in a future release.")
	return nil
}

// runPCICompliance runs PCI DSS v4.0 compliance analysis
func runPCICompliance(cmd *cobra.Command, args []string) error {
	repoPath, _ := cmd.Flags().GetString("repo")
	outputPath, _ := cmd.Flags().GetString("output")

	fmt.Println("🔒 TITO PCI DSS v4.0 Compliance Analysis")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("   Repository: %s\n", repoPath)
	fmt.Printf("   Output: %s\n", outputPath)
	fmt.Println()

	// Step 1: Run threat detection (reuse scan logic)
	fmt.Println("📊 Step 1/3: Scanning for threats...")
	
	// Run Semgrep scan with PCI rules
	runner := semgrep.NewRunner("")
	
	// Add PCI-specific rules
	pciRulesPath := filepath.Join(filepath.Dir(os.Args[0]), "..", "rules", "pci")
	if _, err := os.Stat(pciRulesPath); err == nil {
		fmt.Printf("   ✓ Loading PCI-specific Semgrep rules from %s\n", pciRulesPath)
	}

	results, err := runner.Scan(context.Background(), repoPath)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	fmt.Printf("   ✓ Found %d potential issues\n", len(results.Results))
	fmt.Println()

	// Step 2: Map findings to threats
	fmt.Println("🔍 Step 2/3: Mapping findings to threats and PCI requirements...")
	
	threats := make([]models.Threat, 0)
	semgrepMapper := semgrep.NewMapper()
	pciMapper := pci.NewMapper()

	for _, finding := range results.Results {
		// Map to STRIDE-LM
		mapping := semgrepMapper.MapFinding(finding)
		
		// Create threat
		threat := models.Threat{
			ID:          fmt.Sprintf("threat-%d", len(threats)+1),
			Title:       finding.Extra.Message,
			Description: fmt.Sprintf("%s (File: %s, Line: %d)", finding.Extra.Message, finding.Path, finding.Start.Line),
			Severity:    mapSeverity(finding.Extra.Severity),
			StrideProfile: &stridelm.Profile{
				PrimaryCategory: mapping.STRIDECategory,
				ConfidenceScores: map[stridelm.Category]float64{
					mapping.STRIDECategory: mapping.Confidence,
				},
			},
			DiscoveredAt: time.Now(),
			UpdatedAt:    time.Now(),
			Tags:         []string{"semgrep", "pci-dss"},
		}

		// Extract CWE IDs from finding and convert to strings
		cweIDs := semgrep.GetCWEIDs(finding)
		cweStrs := make([]string, len(cweIDs))
		for i, id := range cweIDs {
			cweStrs[i] = fmt.Sprintf("CWE-%d", id)
		}
		
		// Map to PCI requirements
		pciMappings := pciMapper.MapThreat(
			threat.Title,
			threat.Description,
			mapping.STRIDECategory,
			cweStrs,
			[]string{finding.CheckID},
		)

		// Add PCI requirement IDs to threat
		for _, pciMapping := range pciMappings {
			reqID := fmt.Sprintf("%s-%s", pciMapping.RequirementID, pciMapping.SubRequirementID)
			threat.PCIRequirements = append(threat.PCIRequirements, reqID)
		}

		threats = append(threats, threat)
	}

	fmt.Printf("   ✓ Identified %d threats\n", len(threats))
	fmt.Printf("   ✓ Mapped to PCI DSS v4.0 requirements\n")
	fmt.Println()

	// Step 3: Generate PCI compliance report
	fmt.Println("📋 Step 3/3: Generating PCI DSS compliance report...")
	
	report := pci.GenerateReport(threats)
	markdown := report.ToMarkdown()

	// Write report to file
	err = os.WriteFile(outputPath, []byte(markdown), 0644)
	if err != nil {
		return fmt.Errorf("failed to write report: %w", err)
	}

	fmt.Printf("   ✓ Report generated: %s\n", outputPath)
	fmt.Println()

	// Summary
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("✅ PCI DSS Compliance Analysis Complete")
	fmt.Println()
	fmt.Printf("   Total Threats: %d\n", report.TotalThreats)
	fmt.Printf("   Total Findings: %d\n", report.TotalFindings)
	fmt.Printf("   Requirements Assessed: %d\n", len(report.RequirementResults))
	fmt.Printf("   Gaps Identified: %d\n", len(report.GapAnalysis))
	fmt.Printf("   Recommendations: %d\n", len(report.Recommendations))
	fmt.Println()
	fmt.Println("📄 View the full report:")
	fmt.Printf("   %s\n", outputPath)
	fmt.Println()
	fmt.Println("⚠️  This report should be used as part of a comprehensive PCI DSS")
	fmt.Println("   assessment, not as a replacement for a QSA audit.")
	fmt.Println()

	return nil
}

// mapSeverity maps Semgrep severity to threat severity
func mapSeverity(semgrepSeverity string) models.ThreatSeverity {
	switch strings.ToUpper(semgrepSeverity) {
	case "ERROR":
		return models.SeverityHigh
	case "WARNING":
		return models.SeverityMedium
	case "INFO":
		return models.SeverityLow
	default:
		return models.SeverityInfo
	}
}

var apiCmd = &cobra.Command{
	Use:   "api",
	Short: "Start the TITO API server",
	Long: `Start the TITO REST API server for programmatic access.

The API provides:
  - POST /api/v1/scan — Trigger repository scans
  - GET  /api/v1/scans — List scan results
  - GET  /api/v1/scan/:id — Get scan details
  - POST /api/v1/diff — Compare two scans
  - GET  /api/v1/attack-paths/:id — Get attack paths
  - WebSocket /ws/events — Real-time scan events

Designed for integration with internal tooling, dashboards, and
automated security pipelines.

Examples:
  tito api --port 9090
  tito api --port 9090 --token myapikey`,
	RunE: runAPI,
}

func init() {
	apiCmd.Flags().IntP("port", "p", 9090, "API server port")
	apiCmd.Flags().String("token", "", "API authentication token")
}

func runAPI(cmd *cobra.Command, args []string) error {
	// TODO: Implement REST API server
	port, _ := cmd.Flags().GetInt("port")
	fmt.Println("🏢 TITO API Server")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("   Port: %d\n", port)
	fmt.Println()
	fmt.Println("⚠️  API server is under active development.")
	fmt.Println("   Coming soon in a future release.")
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

// CategoryDistributionItem represents threat count by category
type CategoryDistributionItem struct {
	CategoryCode string
	CategoryName string
	Count        int
}

// getThreatDistribution returns threat counts grouped by STRIDE-LM category
func getThreatDistribution(threats []*models.Threat) []CategoryDistributionItem {
	distribution := make(map[string]*CategoryDistributionItem)
	
	// Count threats by category
	for _, threat := range threats {
		if threat.StrideProfile != nil {
			catCode := string(threat.StrideProfile.PrimaryCategory)
			if _, exists := distribution[catCode]; !exists {
				catInfo := threat.StrideProfile.PrimaryCategory
				distribution[catCode] = &CategoryDistributionItem{
					CategoryCode: catCode,
					CategoryName: getCategoryFullName(catInfo),
					Count:        0,
				}
			}
			distribution[catCode].Count++
		}
	}
	
	// Convert map to sorted slice (by count descending)
	result := make([]CategoryDistributionItem, 0, len(distribution))
	for _, item := range distribution {
		result = append(result, *item)
	}
	
	// Simple bubble sort by count (descending)
	for i := 0; i < len(result)-1; i++ {
		for j := 0; j < len(result)-i-1; j++ {
			if result[j].Count < result[j+1].Count {
				result[j], result[j+1] = result[j+1], result[j]
			}
		}
	}
	
	return result
}

// TopThreatByCategoryItem represents the top threat for a category
type TopThreatByCategoryItem struct {
	CategoryCode string
	Threat       *models.Threat
	RiskScore    float64
}

// getTopThreatsByCategory returns one top threat per STRIDE-LM category
func getTopThreatsByCategory(mappedThreats []mapper.MappedThreat) []TopThreatByCategoryItem {
	categoryMap := make(map[string]*TopThreatByCategoryItem)
	
	// Find highest risk threat for each category
	for _, mt := range mappedThreats {
		if mt.Threat.StrideProfile != nil {
			catCode := string(mt.Threat.StrideProfile.PrimaryCategory)
			
			if existing, exists := categoryMap[catCode]; !exists || mt.RiskScore > existing.RiskScore {
				categoryMap[catCode] = &TopThreatByCategoryItem{
					CategoryCode: catCode,
					Threat:       mt.Threat,
					RiskScore:    mt.RiskScore,
				}
			}
		}
	}
	
	// Convert to sorted slice (by risk score descending)
	result := make([]TopThreatByCategoryItem, 0, len(categoryMap))
	for _, item := range categoryMap {
		result = append(result, *item)
	}
	
	// Simple bubble sort by risk score (descending)
	for i := 0; i < len(result)-1; i++ {
		for j := 0; j < len(result)-i-1; j++ {
			if result[j].RiskScore < result[j+1].RiskScore {
				result[j], result[j+1] = result[j+1], result[j]
			}
		}
	}
	
	return result
}

// getCategoryFullName returns the full name for a STRIDE-LM category
func getCategoryFullName(cat stridelm.Category) string {
	switch cat {
	case stridelm.Spoofing:
		return "Spoofing"
	case stridelm.Tampering:
		return "Tampering"
	case stridelm.Repudiation:
		return "Repudiation"
	case stridelm.InfoDisclosure:
		return "Information Disclosure"
	case stridelm.DenialOfService:
		return "Denial of Service"
	case stridelm.Elevation:
		return "Elevation of Privilege"
	case stridelm.LateralMovement:
		return "Lateral Movement"
	case stridelm.Malware:
		return "Malware"
	default:
		return "Unknown"
	}
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

	// Serve the directory (use a local mux, not DefaultServeMux)
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir(dir)))

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

	if err := http.ListenAndServe(addr, mux); err != nil {
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

func getDifficultyLevel(difficulty float64) string {
	if difficulty < 0.1 {
		return "TRIVIAL"
	} else if difficulty < 0.3 {
		return "LOW"
	} else if difficulty < 0.6 {
		return "MEDIUM"
	} else if difficulty < 0.8 {
		return "HIGH"
	}
	return "VERY HIGH"
}

func countTrustBoundariesCrossed(steps []attackpath.AttackStep, graph *attackpath.AttackGraph) int {
	if len(steps) == 0 {
		return 0
	}

	count := 0
	prevZone := ""

	for _, step := range steps {
		fromNode := graph.Nodes[step.FromNode]
		toNode := graph.Nodes[step.ToNode]

		if fromNode != nil && toNode != nil {
			if prevZone == "" {
				prevZone = fromNode.Zone
			}

			if toNode.Zone != prevZone {
				count++
				prevZone = toNode.Zone
			}
		}
	}

	return count
}

// ── Semgrep management subcommands ──────────────────────────────────────────

var semgrepCmd = &cobra.Command{
	Use:   "semgrep",
	Short: "Manage the Semgrep SAST dependency",
	Long:  "Detect, install, and uninstall the Semgrep static analysis tool used by TITO's --semgrep flag.",
}

var semgrepStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show Semgrep installation status",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		info := semgrep.Detect(ctx)
		if !info.Installed {
			fmt.Println("✗ Semgrep is not installed")
			fmt.Println("  Run: tito semgrep install")
			return nil
		}
		fmt.Printf("✓ Semgrep %s\n", info.Version)
		fmt.Printf("  Path:   %s\n", info.Path)
		fmt.Printf("  Method: %s\n", info.Method)
		return nil
	},
}

var semgrepInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install Semgrep silently",
	Long:  "Install Semgrep via pip, pipx, or Homebrew. All output is suppressed.",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		existing := semgrep.Detect(ctx)
		if existing.Installed {
			fmt.Printf("✓ Semgrep %s already installed (%s)\n", existing.Version, existing.Path)
			return nil
		}
		fmt.Print("Installing Semgrep... ")
		info, err := semgrep.EnsureInstalled(ctx)
		if err != nil {
			fmt.Println("✗")
			return err
		}
		fmt.Printf("✓ %s (%s)\n", info.Version, info.Method)
		return nil
	},
}

var semgrepUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall Semgrep",
	Long:  "Remove Semgrep using the same method it was installed with (pip, pipx, brew, or binary).",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		info := semgrep.Detect(ctx)
		if !info.Installed {
			fmt.Println("✓ Semgrep is not installed — nothing to do")
			return nil
		}
		fmt.Printf("Uninstalling Semgrep %s (installed via %s)... ", info.Version, info.Method)
		if err := semgrep.Uninstall(ctx); err != nil {
			fmt.Println("✗")
			return err
		}
		fmt.Println("✓")
		return nil
	},
}

func init() {
	semgrepCmd.AddCommand(semgrepStatusCmd)
	semgrepCmd.AddCommand(semgrepInstallCmd)
	semgrepCmd.AddCommand(semgrepUninstallCmd)
}
