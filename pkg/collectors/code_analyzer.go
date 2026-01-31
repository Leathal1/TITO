package collectors

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Leathal1/TITO/pkg/models"
	"github.com/Leathal1/TITO/pkg/scanner"
	"github.com/Leathal1/TITO/pkg/stridelm"
)

// CodeAnalyzer analyzes scanned repositories to generate code-specific threats
type CodeAnalyzer struct {
	*BaseCollector
	repo *scanner.Repository
}

// NewCodeAnalyzer creates a new code analyzer
func NewCodeAnalyzer(repo *scanner.Repository) *CodeAnalyzer {
	return &CodeAnalyzer{
		BaseCollector: NewBaseCollector("CodeAnalyzer"),
		repo:          repo,
	}
}

// Collect analyzes the repository and returns discovered threats
func (ca *CodeAnalyzer) Collect(ctx context.Context) ([]*models.Threat, error) {
	ca.ClearErrors()

	if ca.repo == nil {
		return nil, fmt.Errorf("no repository provided")
	}

	threats := make([]*models.Threat, 0)

	// Analyze assets for threats
	assetThreats := ca.analyzeAssets(ctx)
	threats = append(threats, assetThreats...)

	// Analyze data flows for threats
	dataFlowThreats := ca.analyzeDataFlows(ctx)
	threats = append(threats, dataFlowThreats...)

	// Analyze for agentic/MAESTRO patterns
	maestroThreats := ca.analyzeMAESTROPatterns(ctx)
	threats = append(threats, maestroThreats...)

	ca.RecordRun()
	return threats, nil
}

// analyzeAssets analyzes repository assets for security threats
func (ca *CodeAnalyzer) analyzeAssets(ctx context.Context) []*models.Threat {
	threats := make([]*models.Threat, 0)

	// Track assets to avoid duplication
	seen := make(map[string]bool)

	for _, asset := range ca.repo.Assets {
		// Skip if we've already flagged this location
		locationKey := fmt.Sprintf("%s:%d", asset.Location.File, asset.Location.Line)
		if seen[locationKey] {
			continue
		}

		switch asset.Type {
		case scanner.AssetAPI:
			// Rule 1: API endpoints without auth patterns nearby
			if !ca.hasNearbyAuth(asset) {
				threat := ca.createThreat(
					"Unauthenticated API Endpoint",
					fmt.Sprintf("API endpoint '%s' at %s:%d may lack authentication checks", 
						asset.Name, asset.Location.File, asset.Location.Line),
					models.SeverityHigh,
					[]stridelm.Category{stridelm.Spoofing, stridelm.Elevation},
					[]string{
						"Implement authentication middleware for all API endpoints",
						"Verify authorization checks are in place before processing requests",
						"Use framework-provided authentication guards or decorators",
						"Review access control policies for this endpoint",
					},
					[]models.ThreatIndicator{ca.createAssetIndicator(asset)},
					asset,
				)
				threats = append(threats, threat)
				seen[locationKey] = true
			}

		case scanner.AssetDatabase:
			// Rule 2: Database operations with string concatenation (SQL injection risk)
			if ca.hasSQLInjectionRisk(asset) {
				threat := ca.createThreat(
					"Potential SQL Injection",
					fmt.Sprintf("Database operation at %s:%d may be vulnerable to SQL injection due to string concatenation",
						asset.Location.File, asset.Location.Line),
					models.SeverityCritical,
					[]stridelm.Category{stridelm.Tampering, stridelm.InfoDisclosure},
					[]string{
						"CRITICAL: Use parameterized queries or prepared statements",
						"Never concatenate user input into SQL queries",
						"Use an ORM with built-in SQL injection protection",
						"Validate and sanitize all inputs before database operations",
					},
					[]models.ThreatIndicator{ca.createAssetIndicator(asset)},
					asset,
				)
				threats = append(threats, threat)
				seen[locationKey] = true
			}

		case scanner.AssetSecret:
			// Rule 3: Hardcoded secrets/credentials
			if ca.isHardcodedSecret(asset) {
				threat := ca.createThreat(
					"Hardcoded Credential Detected",
					fmt.Sprintf("Hardcoded credential found: %s at %s:%d",
						asset.Name, asset.Location.File, asset.Location.Line),
					models.SeverityCritical,
					[]stridelm.Category{stridelm.InfoDisclosure},
					[]string{
						"CRITICAL: Remove hardcoded credentials immediately",
						"Use environment variables or secure secret management",
						"Rotate all exposed credentials",
						"Implement secret scanning in CI/CD pipeline",
						"Consider using HashiCorp Vault, AWS Secrets Manager, or similar",
					},
					[]models.ThreatIndicator{ca.createAssetIndicator(asset)},
					asset,
				)
				threats = append(threats, threat)
				seen[locationKey] = true
			}

		case scanner.AssetNetwork:
			// Rule 4: External API calls without TLS verification
			if ca.lacksSecureTransport(asset) {
				threat := ca.createThreat(
					"Insecure External API Call",
					fmt.Sprintf("External API call at %s:%d may lack TLS verification",
						asset.Location.File, asset.Location.Line),
					models.SeverityMedium,
					[]stridelm.Category{stridelm.Tampering},
					[]string{
						"Enable TLS/SSL certificate verification",
						"Use HTTPS for all external API calls",
						"Implement certificate pinning for critical services",
						"Reject connections with invalid certificates",
					},
					[]models.ThreatIndicator{ca.createAssetIndicator(asset)},
					asset,
				)
				threats = append(threats, threat)
				seen[locationKey] = true
			}

		case scanner.AssetFileSystem:
			// Rule 5: File operations with user-controlled paths
			if asset.Sensitive {
				threat := ca.createThreat(
					"Path Traversal Risk",
					fmt.Sprintf("File operation at %s:%d may be vulnerable to path traversal",
						asset.Location.File, asset.Location.Line),
					models.SeverityHigh,
					[]stridelm.Category{stridelm.Tampering, stridelm.InfoDisclosure},
					[]string{
						"Validate and sanitize all file paths from user input",
						"Use allowlist of permitted directories",
						"Resolve paths and check they stay within allowed boundaries",
						"Use framework-provided safe file handling APIs",
					},
					[]models.ThreatIndicator{ca.createAssetIndicator(asset)},
					asset,
				)
				threats = append(threats, threat)
				seen[locationKey] = true
			}

		case scanner.AssetCrypto:
			// Rule 6: Crypto operations (check for error handling)
			if !ca.hasProperErrorHandling(asset) {
				threat := ca.createThreat(
					"Cryptographic Error Leakage",
					fmt.Sprintf("Cryptographic operation at %s:%d may leak errors or timing information",
						asset.Location.File, asset.Location.Line),
					models.SeverityMedium,
					[]stridelm.Category{stridelm.InfoDisclosure},
					[]string{
						"Implement proper error handling for cryptographic operations",
						"Avoid leaking detailed error messages to users",
						"Use constant-time comparison for sensitive operations",
						"Log crypto failures securely without exposing details",
					},
					[]models.ThreatIndicator{ca.createAssetIndicator(asset)},
					asset,
				)
				threats = append(threats, threat)
				seen[locationKey] = true
			}

		case scanner.AssetAuth:
			// Rule 7: Session/auth tokens stored insecurely
			if ca.hasInsecureStorage(asset) {
				threat := ca.createThreat(
					"Insecure Token Storage",
					fmt.Sprintf("Auth token at %s:%d may be stored insecurely",
						asset.Location.File, asset.Location.Line),
					models.SeverityHigh,
					[]stridelm.Category{stridelm.Spoofing},
					[]string{
						"Store tokens in secure, httpOnly cookies",
						"Use secure session management libraries",
						"Implement token expiration and rotation",
						"Never store tokens in localStorage without encryption",
					},
					[]models.ThreatIndicator{ca.createAssetIndicator(asset)},
					asset,
				)
				threats = append(threats, threat)
				seen[locationKey] = true
			}
		}
	}

	return threats
}

// analyzeDataFlows analyzes data flows for security threats
func (ca *CodeAnalyzer) analyzeDataFlows(ctx context.Context) []*models.Threat {
	threats := make([]*models.Threat, 0)

	for _, flow := range ca.repo.DataFlows {
		// Rule 8: Sensitive data flowing to external endpoints
		if flow.Sensitive && ca.isExternalFlow(flow) {
			threat := ca.createDataFlowThreat(
				"Sensitive Data Exposure",
				fmt.Sprintf("Sensitive data flows from %s:%d to external endpoint %s:%d",
					flow.Source.File, flow.Source.Line,
					flow.Destination.File, flow.Destination.Line),
				models.SeverityHigh,
				[]stridelm.Category{stridelm.InfoDisclosure},
				[]string{
					"Encrypt sensitive data before external transmission",
					"Minimize data exposure - only send what's necessary",
					"Implement data loss prevention (DLP) controls",
					"Review and log all external data transmissions",
				},
				flow,
			)
			threats = append(threats, threat)
		}

		// Rule 9: Data crossing trust boundaries without validation
		if ca.crossesTrustBoundary(flow) && !ca.hasValidation(flow) {
			threat := ca.createDataFlowThreat(
				"Unvalidated Trust Boundary Crossing",
				fmt.Sprintf("Data crosses trust boundary from %s:%d to %s:%d without apparent validation",
					flow.Source.File, flow.Source.Line,
					flow.Destination.File, flow.Destination.Line),
				models.SeverityMedium,
				[]stridelm.Category{stridelm.Tampering},
				[]string{
					"Validate all data crossing trust boundaries",
					"Implement input validation and sanitization",
					"Use schema validation for structured data",
					"Apply principle of least privilege to data access",
				},
				flow,
			)
			threats = append(threats, threat)
		}

		// Rule 10: Authentication data flowing through non-encrypted channels
		if ca.isAuthFlow(flow) && !ca.isEncrypted(flow) {
			threat := ca.createDataFlowThreat(
				"Authentication Data in Cleartext",
				fmt.Sprintf("Authentication data may traverse unencrypted channel from %s:%d to %s:%d",
					flow.Source.File, flow.Source.Line,
					flow.Destination.File, flow.Destination.Line),
				models.SeverityHigh,
				[]stridelm.Category{stridelm.Spoofing},
				[]string{
					"URGENT: Use TLS/HTTPS for all authentication flows",
					"Never transmit credentials over unencrypted connections",
					"Implement end-to-end encryption for sensitive auth data",
					"Use secure authentication protocols (OAuth2, SAML, etc.)",
				},
				flow,
			)
			threats = append(threats, threat)
		}
	}

	return threats
}

// analyzeMAESTROPatterns analyzes for agentic AI/MAESTRO-specific threats
func (ca *CodeAnalyzer) analyzeMAESTROPatterns(ctx context.Context) []*models.Threat {
	threats := make([]*models.Threat, 0)

	// Scan all assets for agentic patterns
	hasLLMFramework := false
	hasToolLoading := false
	hasInterServiceComm := false

	llmPatterns := []string{"openai", "anthropic", "langchain", "llama", "gpt", "claude", "bedrock"}
	toolPatterns := []string{"plugin", "tool", "function_calling", "tooling"}
	commPatterns := []string{"grpc", "graphql", "websocket", "microservice"}

	for _, asset := range ca.repo.Assets {
		desc := strings.ToLower(asset.Description)
		name := strings.ToLower(asset.Name)
		file := strings.ToLower(asset.Location.File)

		// Rule 11: LLM/AI framework imports
		for _, pattern := range llmPatterns {
			if strings.Contains(desc, pattern) || strings.Contains(name, pattern) || strings.Contains(file, pattern) {
				if !hasLLMFramework {
					threat := ca.createThreat(
						"LLM Integration - Prompt Injection Risk",
						fmt.Sprintf("LLM/AI framework detected at %s:%d - susceptible to prompt injection attacks",
							asset.Location.File, asset.Location.Line),
						models.SeverityHigh,
						[]stridelm.Category{stridelm.Tampering, stridelm.Elevation},
						[]string{
							"Implement prompt injection detection and filtering",
							"Use structured outputs and validation",
							"Separate system prompts from user inputs",
							"Apply MAESTRO Layer 1 (Foundation Model) security controls",
							"Monitor and log all LLM interactions for anomalies",
						},
						[]models.ThreatIndicator{ca.createAssetIndicator(asset)},
						asset,
					)
					threat.Tags = append(threat.Tags, "MAESTRO", "AI", "LLM", "prompt-injection")
					threats = append(threats, threat)
					hasLLMFramework = true
				}
			}
		}

		// Rule 12: Tool/plugin loading patterns
		for _, pattern := range toolPatterns {
			if strings.Contains(desc, pattern) || strings.Contains(name, pattern) {
				if !hasToolLoading {
					threat := ca.createThreat(
						"Dynamic Tool Loading - Tool Poisoning Risk",
						fmt.Sprintf("Dynamic tool/plugin loading detected at %s:%d - risk of tool poisoning",
							asset.Location.File, asset.Location.Line),
						models.SeverityHigh,
						[]stridelm.Category{stridelm.Tampering, stridelm.Elevation},
						[]string{
							"Validate and sanitize all tool definitions",
							"Use allowlist for permitted tools and functions",
							"Implement tool execution sandboxing",
							"Apply MAESTRO Layer 4 (Tooling) security controls",
							"Monitor tool invocations for suspicious patterns",
						},
						[]models.ThreatIndicator{ca.createAssetIndicator(asset)},
						asset,
					)
					threat.Tags = append(threat.Tags, "MAESTRO", "tooling", "plugins")
					threats = append(threats, threat)
					hasToolLoading = true
				}
			}
		}

		// Rule 13: Inter-process/service communication
		for _, pattern := range commPatterns {
			if strings.Contains(desc, pattern) || strings.Contains(name, pattern) {
				if !hasInterServiceComm {
					threat := ca.createThreat(
						"Inter-Agent Communication - Authentication Risk",
						fmt.Sprintf("Inter-service communication detected at %s:%d - may lack mutual authentication",
							asset.Location.File, asset.Location.Line),
						models.SeverityMedium,
						[]stridelm.Category{stridelm.Spoofing, stridelm.Tampering},
						[]string{
							"Implement mutual TLS (mTLS) for service-to-service communication",
							"Use service mesh for authentication and authorization",
							"Validate all inter-agent messages",
							"Apply MAESTRO Layer 5 (Agent Communication) security controls",
							"Implement message signing and verification",
						},
						[]models.ThreatIndicator{ca.createAssetIndicator(asset)},
						asset,
					)
					threat.Tags = append(threat.Tags, "MAESTRO", "microservices", "agent-comm")
					threats = append(threats, threat)
					hasInterServiceComm = true
				}
			}
		}
	}

	return threats
}

// Helper methods for threat detection logic

func (ca *CodeAnalyzer) hasNearbyAuth(asset scanner.Asset) bool {
	// Check if there's an auth asset within 50 lines in the same file
	for _, other := range ca.repo.Assets {
		if other.Type == scanner.AssetAuth &&
			other.Location.File == asset.Location.File &&
			abs(other.Location.Line-asset.Location.Line) < 50 {
			return true
		}
	}
	return false
}

func (ca *CodeAnalyzer) hasSQLInjectionRisk(asset scanner.Asset) bool {
	// Check if description contains string concatenation patterns
	desc := strings.ToLower(asset.Description)
	indicators := []string{"+", "concat", "sprintf", "format", "f\"", "${", "interpolat"}
	for _, indicator := range indicators {
		if strings.Contains(desc, indicator) {
			return true
		}
	}
	return false
}

func (ca *CodeAnalyzer) isHardcodedSecret(asset scanner.Asset) bool {
	// Secrets that are in .env files are configuration, not hardcoded
	if strings.Contains(asset.Location.File, ".env") {
		return false
	}
	// Otherwise, if it's marked as a secret asset in code files, flag it
	return asset.Type == scanner.AssetSecret && !strings.HasSuffix(asset.Location.File, ".env")
}

func (ca *CodeAnalyzer) lacksSecureTransport(asset scanner.Asset) bool {
	desc := strings.ToLower(asset.Description)
	// Check for indicators of insecure transport
	if strings.Contains(desc, "http://") && !strings.Contains(desc, "https://") {
		return true
	}
	if strings.Contains(desc, "insecure") || strings.Contains(desc, "skip") && strings.Contains(desc, "verify") {
		return true
	}
	return false
}

func (ca *CodeAnalyzer) hasProperErrorHandling(asset scanner.Asset) bool {
	// Simplified heuristic: assume crypto operations need scrutiny
	// In real implementation, would check surrounding code
	return false // Flag all crypto operations for review
}

func (ca *CodeAnalyzer) hasInsecureStorage(asset scanner.Asset) bool {
	desc := strings.ToLower(asset.Description)
	name := strings.ToLower(asset.Name)
	// Check for indicators of insecure storage
	insecurePatterns := []string{"localstorage", "sessionstorage", "cookie", "plaintext"}
	for _, pattern := range insecurePatterns {
		if strings.Contains(desc, pattern) || strings.Contains(name, pattern) {
			return true
		}
	}
	return false
}

func (ca *CodeAnalyzer) isExternalFlow(flow scanner.DataFlow) bool {
	// Check if flow goes to an external/network asset
	for _, asset := range ca.repo.Assets {
		if asset.Location.File == flow.Destination.File &&
			asset.Location.Line == flow.Destination.Line &&
			asset.Type == scanner.AssetNetwork {
			return true
		}
	}
	return false
}

func (ca *CodeAnalyzer) crossesTrustBoundary(flow scanner.DataFlow) bool {
	// Flows from API endpoints to other components cross trust boundaries
	for _, asset := range ca.repo.Assets {
		if asset.Location.File == flow.Source.File &&
			abs(asset.Location.Line-flow.Source.Line) < 10 &&
			asset.Type == scanner.AssetAPI {
			return true
		}
	}
	return false
}

func (ca *CodeAnalyzer) hasValidation(flow scanner.DataFlow) bool {
	// Simplified: assume flows need validation unless proven otherwise
	// Real implementation would check for validation frameworks/patterns
	return false
}

func (ca *CodeAnalyzer) isAuthFlow(flow scanner.DataFlow) bool {
	// Check if flow involves authentication assets
	for _, asset := range ca.repo.Assets {
		if asset.Type == scanner.AssetAuth &&
			((asset.Location.File == flow.Source.File && abs(asset.Location.Line-flow.Source.Line) < 10) ||
				(asset.Location.File == flow.Destination.File && abs(asset.Location.Line-flow.Destination.Line) < 10)) {
			return true
		}
	}
	return false
}

func (ca *CodeAnalyzer) isEncrypted(flow scanner.DataFlow) bool {
	// Check if flow involves crypto assets or TLS
	for _, asset := range ca.repo.Assets {
		if asset.Type == scanner.AssetCrypto &&
			((asset.Location.File == flow.Source.File && abs(asset.Location.Line-flow.Source.Line) < 20) ||
				(asset.Location.File == flow.Destination.File && abs(asset.Location.Line-flow.Destination.Line) < 20)) {
			return true
		}
	}
	return false
}

// Threat creation helpers

func (ca *CodeAnalyzer) createThreat(
	title string,
	description string,
	severity models.ThreatSeverity,
	categories []stridelm.Category,
	recommendations []string,
	indicators []models.ThreatIndicator,
	asset scanner.Asset,
) *models.Threat {
	now := time.Now()

	// Build STRIDE profile
	strideProfile := &stridelm.Profile{
		PrimaryCategory:     categories[0],
		SecondaryCategories: []stridelm.Category{},
		ConfidenceScores:    make(map[stridelm.Category]float64),
	}
	
	// Set confidence scores for each category
	for i, cat := range categories {
		if i == 0 {
			strideProfile.ConfidenceScores[cat] = 0.85 // High confidence for primary
		} else {
			strideProfile.ConfidenceScores[cat] = 0.65 // Medium confidence for secondary
			strideProfile.SecondaryCategories = append(strideProfile.SecondaryCategories, cat)
		}
	}

	// Create threat context
	context := models.ThreatContext{
		AffectsKnownAssets:    true,
		AffectedAssetTypes:    []string{string(asset.Type)},
		AffectedTechnologies:  []string{ca.repo.Language, ca.repo.Framework},
		ExposureLevel:         ca.determineExposureLevel(asset),
		AttackComplexity:      "low",
		ExploitationStatus:    models.ExploitationTheoretical,
		MitigationAvailable:   true,
		MitigationComplexity:  "medium",
	}

	threat := &models.Threat{
		ID:                 fmt.Sprintf("code-threat-%s-%d", asset.ID, now.Unix()),
		Title:              title,
		Description:        description,
		Severity:           severity,
		StrideProfile:      strideProfile,
		Indicators:         indicators,
		Context:            context,
		DiscoveredAt:       now,
		UpdatedAt:          now,
		RecommendedActions: recommendations,
		Tags:               []string{"code-analysis", string(severity), string(asset.Type)},
		SourceFeeds:        []string{"CodeAnalyzer"},
	}

	threat.UpdatePriority()
	return threat
}

func (ca *CodeAnalyzer) createDataFlowThreat(
	title string,
	description string,
	severity models.ThreatSeverity,
	categories []stridelm.Category,
	recommendations []string,
	flow scanner.DataFlow,
) *models.Threat {
	now := time.Now()

	// Build STRIDE profile
	strideProfile := &stridelm.Profile{
		PrimaryCategory:     categories[0],
		SecondaryCategories: []stridelm.Category{},
		ConfidenceScores:    make(map[stridelm.Category]float64),
	}
	
	for i, cat := range categories {
		if i == 0 {
			strideProfile.ConfidenceScores[cat] = 0.80
		} else {
			strideProfile.ConfidenceScores[cat] = 0.60
			strideProfile.SecondaryCategories = append(strideProfile.SecondaryCategories, cat)
		}
	}

	// Create indicator for the data flow
	indicator := models.ThreatIndicator{
		ID:          fmt.Sprintf("flow-ind-%s-%d", flow.ID, now.Unix()),
		Type:        models.IndicatorAttackPattern,
		Value:       flow.DataType,
		Description: fmt.Sprintf("Data flow: %s -> %s", flow.Source.File, flow.Destination.File),
		Confidence:  0.75,
		FirstSeen:   now,
		LastSeen:    now,
		Tags:        []string{"dataflow", flow.DataType},
		Source:      "CodeAnalyzer",
	}

	context := models.ThreatContext{
		AffectsKnownAssets:    true,
		AffectedAssetTypes:    []string{"dataflow"},
		AffectedTechnologies:  []string{ca.repo.Language, ca.repo.Framework},
		ExposureLevel:         "internal",
		AttackComplexity:      "low",
		ExploitationStatus:    models.ExploitationTheoretical,
		MitigationAvailable:   true,
		MitigationComplexity:  "medium",
	}

	threat := &models.Threat{
		ID:                 fmt.Sprintf("flow-threat-%s-%d", flow.ID, now.Unix()),
		Title:              title,
		Description:        description,
		Severity:           severity,
		StrideProfile:      strideProfile,
		Indicators:         []models.ThreatIndicator{indicator},
		Context:            context,
		DiscoveredAt:       now,
		UpdatedAt:          now,
		RecommendedActions: recommendations,
		Tags:               []string{"dataflow", string(severity)},
		SourceFeeds:        []string{"CodeAnalyzer"},
	}

	threat.UpdatePriority()
	return threat
}

func (ca *CodeAnalyzer) createAssetIndicator(asset scanner.Asset) models.ThreatIndicator {
	now := time.Now()
	return models.ThreatIndicator{
		ID:          fmt.Sprintf("asset-ind-%s-%d", asset.ID, now.Unix()),
		Type:        models.IndicatorAttackPattern,
		Value:       asset.Name,
		Description: fmt.Sprintf("%s at %s:%d", asset.Type, asset.Location.File, asset.Location.Line),
		Confidence:  0.85,
		FirstSeen:   now,
		LastSeen:    now,
		Tags:        []string{string(asset.Type), asset.Location.File},
		Source:      "CodeAnalyzer",
	}
}

func (ca *CodeAnalyzer) determineExposureLevel(asset scanner.Asset) string {
	if asset.Exposed {
		return "internet"
	}
	if asset.Type == scanner.AssetAPI {
		return "internal"
	}
	return "isolated"
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
