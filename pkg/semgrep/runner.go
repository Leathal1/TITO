package semgrep

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// Runner executes Semgrep scans
type Runner struct {
	semgrepPath string
	config      string
}

// NewRunner creates a new Semgrep runner
func NewRunner(config string) *Runner {
	if config == "" {
		config = "auto"
	}
	return &Runner{
		semgrepPath: "semgrep",
		config:      config,
	}
}

// Scan runs a Semgrep scan on the specified directory
func (r *Runner) Scan(ctx context.Context, targetPath string) (*SemgrepOutput, error) {
	// Check if semgrep is installed
	if err := r.checkInstalled(ctx); err != nil {
		return nil, fmt.Errorf("semgrep not found: %w", err)
	}

	// Build command
	args := []string{
		"scan",
		"--json",
		"--config", r.config,
		"--no-git-ignore", // Include all files
		targetPath,
	}

	cmd := exec.CommandContext(ctx, r.semgrepPath, args...)

	// Capture stdout (JSON) and stderr (progress) separately so
	// progress messages don't contaminate the JSON output.
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil && stdout.Len() == 0 {
		return nil, fmt.Errorf("semgrep scan failed: %w: %s", err, stderr.String())
	}

	// Parse JSON output from stdout only
	var result SemgrepOutput
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		return nil, fmt.Errorf("failed to parse semgrep output: %w", err)
	}

	return &result, nil
}

// ScanWithRules runs Semgrep with specific rules
func (r *Runner) ScanWithRules(ctx context.Context, targetPath string, rules []string) (*SemgrepOutput, error) {
	if len(rules) == 0 {
		return r.Scan(ctx, targetPath)
	}

	// Check if semgrep is installed
	if err := r.checkInstalled(ctx); err != nil {
		return nil, fmt.Errorf("semgrep not found: %w", err)
	}

	// Build command with multiple --config flags
	args := []string{
		"scan",
		"--json",
	}

	for _, rule := range rules {
		args = append(args, "--config", rule)
	}

	args = append(args, "--no-git-ignore", targetPath)

	cmd := exec.CommandContext(ctx, r.semgrepPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil && stdout.Len() == 0 {
		return nil, fmt.Errorf("semgrep scan failed: %w: %s", err, stderr.String())
	}

	// Parse JSON output from stdout only
	var result SemgrepOutput
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		return nil, fmt.Errorf("failed to parse semgrep output: %w", err)
	}

	return &result, nil
}

// checkInstalled ensures semgrep is available, auto-installing silently if needed.
func (r *Runner) checkInstalled(ctx context.Context) error {
	info, err := EnsureInstalled(ctx)
	if err != nil {
		return err
	}
	// Use the detected path for all subsequent commands
	if info.Path != "" {
		r.semgrepPath = info.Path
	}
	return nil
}

// FilterByConfidence filters findings by minimum confidence level
func FilterByConfidence(findings []Finding, minConfidence ConfidenceLevel) []Finding {
	if minConfidence == "" {
		return findings
	}

	confidenceOrder := map[ConfidenceLevel]int{
		ConfidenceHigh:   3,
		ConfidenceMedium: 2,
		ConfidenceLow:    1,
	}

	minLevel := confidenceOrder[minConfidence]
	var filtered []Finding

	for _, finding := range findings {
		confidence := ConfidenceLevel(strings.ToUpper(finding.Extra.Metadata.Confidence))
		if confidenceOrder[confidence] >= minLevel {
			filtered = append(filtered, finding)
		}
	}

	return filtered
}

// FilterBySeverity filters findings by minimum severity level
func FilterBySeverity(findings []Finding, minSeverity SeverityLevel) []Finding {
	if minSeverity == "" {
		return findings
	}

	severityOrder := map[SeverityLevel]int{
		SeverityError:   3,
		SeverityWarning: 2,
		SeverityInfo:    1,
	}

	minLevel := severityOrder[minSeverity]
	var filtered []Finding

	for _, finding := range findings {
		severity := SeverityLevel(strings.ToUpper(finding.Extra.Severity))
		if severityOrder[severity] >= minLevel {
			filtered = append(filtered, finding)
		}
	}

	return filtered
}

// GetCWEIDs extracts CWE IDs from a finding
func GetCWEIDs(finding Finding) []int {
	cweIDs := make([]int, 0)

	for _, cwe := range finding.Extra.Metadata.CWE {
		// CWE format: "CWE-79" or "79"
		cweStr := strings.TrimPrefix(cwe, "CWE-")
		var cweID int
		if _, err := fmt.Sscanf(cweStr, "%d", &cweID); err == nil {
			cweIDs = append(cweIDs, cweID)
		}
	}

	return cweIDs
}

// SummaryStats provides summary statistics for scan results
type SummaryStats struct {
	TotalFindings int
	BySeverity    map[SeverityLevel]int
	ByConfidence  map[ConfidenceLevel]int
	UniqueCWEs    int
	UniqueRules   int
}

// GetSummaryStats calculates summary statistics from findings
func GetSummaryStats(findings []Finding) SummaryStats {
	stats := SummaryStats{
		TotalFindings: len(findings),
		BySeverity:    make(map[SeverityLevel]int),
		ByConfidence:  make(map[ConfidenceLevel]int),
	}

	cweSet := make(map[string]bool)
	ruleSet := make(map[string]bool)

	for _, finding := range findings {
		// Count by severity
		severity := SeverityLevel(strings.ToUpper(finding.Extra.Severity))
		stats.BySeverity[severity]++

		// Count by confidence
		confidence := ConfidenceLevel(strings.ToUpper(finding.Extra.Metadata.Confidence))
		stats.ByConfidence[confidence]++

		// Track unique CWEs
		for _, cwe := range finding.Extra.Metadata.CWE {
			cweSet[cwe] = true
		}

		// Track unique rules
		ruleSet[finding.CheckID] = true
	}

	stats.UniqueCWEs = len(cweSet)
	stats.UniqueRules = len(ruleSet)

	return stats
}
