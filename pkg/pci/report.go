package pci

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Leathal1/TITO/pkg/models"
	"github.com/Leathal1/TITO/pkg/stridelm"
)

// ComplianceReport represents a PCI DSS compliance report
type ComplianceReport struct {
	GeneratedAt     time.Time
	TotalThreats    int
	TotalFindings   int
	RequirementResults map[string]*RequirementResult
	GapAnalysis     []Gap
	Recommendations []Recommendation
}

// RequirementResult represents findings for a single requirement
type RequirementResult struct {
	Requirement      Requirement
	SubRequirementResults map[string]*SubRequirementResult
	Status           RequirementStatus
	FindingsCount    int
	ThreatIDs        []string
}

// SubRequirementResult represents findings for a sub-requirement
type SubRequirementResult struct {
	SubRequirement SubRequirement
	Status         RequirementStatus
	FindingsCount  int
	Threats        []models.Threat
	HighestSeverity models.ThreatSeverity
}

// Gap represents a compliance gap (requirement with no findings)
type Gap struct {
	Requirement    Requirement
	SubRequirement SubRequirement
	Reason         string
}

// Recommendation represents a prioritized remediation recommendation
type Recommendation struct {
	Priority       int // 1 = highest
	Requirement    Requirement
	SubRequirement SubRequirement
	ThreatCount    int
	HighestSeverity models.ThreatSeverity
	Action         string
}

// GenerateReport generates a PCI DSS compliance report from threats
func GenerateReport(threats []models.Threat) *ComplianceReport {
	report := &ComplianceReport{
		GeneratedAt:        time.Now(),
		TotalThreats:       len(threats),
		TotalFindings:      0,
		RequirementResults: make(map[string]*RequirementResult),
		GapAnalysis:        make([]Gap, 0),
		Recommendations:    make([]Recommendation, 0),
	}

	// Initialize all requirements
	allReqs := AllRequirements()
	for _, req := range allReqs {
		report.RequirementResults[req.ID] = &RequirementResult{
			Requirement:           req,
			SubRequirementResults: make(map[string]*SubRequirementResult),
			Status:                StatusNotTested,
			FindingsCount:         0,
			ThreatIDs:             make([]string, 0),
		}

		// Initialize sub-requirements
		for _, subReq := range req.SubRequirements {
			if subReq.Relevant {
				report.RequirementResults[req.ID].SubRequirementResults[subReq.ID] = &SubRequirementResult{
					SubRequirement:  subReq,
					Status:          StatusNotTested,
					FindingsCount:   0,
					Threats:         make([]models.Threat, 0),
					HighestSeverity: models.SeverityInfo,
				}
			}
		}
	}

	// Process each threat
	mapper := NewMapper()
	for _, threat := range threats {
		// Extract CWE IDs and Semgrep rule IDs (would come from threat metadata in real implementation)
		cweIDs := threat.CVEIDs // Placeholder - would extract CWEs from threat
		semgrepRuleIDs := make([]string, 0) // Placeholder - would come from threat metadata

		// Map threat to PCI requirements
		// Get STRIDE category from threat profile
		var strideCategory stridelm.Category
		if threat.StrideProfile != nil {
			strideCategory = threat.StrideProfile.PrimaryCategory
		}
		
		mappings := mapper.MapThreat(
			threat.Title,
			threat.Description,
			strideCategory,
			cweIDs,
			semgrepRuleIDs,
		)

		// Add threat to mapped requirements
		for _, mapping := range mappings {
			if reqResult, ok := report.RequirementResults[mapping.RequirementID]; ok {
				reqResult.FindingsCount++
				reqResult.ThreatIDs = append(reqResult.ThreatIDs, threat.ID)

				// Update sub-requirement
				if subReqResult, ok := reqResult.SubRequirementResults[mapping.SubRequirementID]; ok {
					subReqResult.FindingsCount++
					subReqResult.Threats = append(subReqResult.Threats, threat)

					// Update highest severity
					if threat.Severity.Score() > subReqResult.HighestSeverity.Score() {
						subReqResult.HighestSeverity = threat.Severity
					}

					// Update status based on severity
					subReqResult.Status = determineStatus(subReqResult.HighestSeverity, subReqResult.FindingsCount)
				}

				report.TotalFindings++
			}
		}
	}

	// Determine overall requirement statuses
	for _, reqResult := range report.RequirementResults {
		reqResult.Status = aggregateSubRequirementStatuses(reqResult.SubRequirementResults)
	}

	// Generate gap analysis
	report.GapAnalysis = identifyGaps(report.RequirementResults)

	// Generate recommendations
	report.Recommendations = generateRecommendations(report.RequirementResults)

	return report
}

// determineStatus determines status based on threat severity and count
func determineStatus(highestSeverity models.ThreatSeverity, findingCount int) RequirementStatus {
	if findingCount == 0 {
		return StatusNotTested
	}

	switch highestSeverity {
	case models.SeverityCritical, models.SeverityHigh:
		return StatusFail
	case models.SeverityMedium:
		return StatusPartial
	case models.SeverityLow, models.SeverityInfo:
		if findingCount > 5 {
			return StatusPartial
		}
		return StatusPass
	}

	return StatusNotTested
}

// aggregateSubRequirementStatuses combines sub-requirement statuses into overall requirement status
func aggregateSubRequirementStatuses(subResults map[string]*SubRequirementResult) RequirementStatus {
	if len(subResults) == 0 {
		return StatusNotTested
	}

	hasFail := false
	hasPartial := false
	hasPass := false
	allNotTested := true

	for _, subResult := range subResults {
		if subResult.Status != StatusNotTested {
			allNotTested = false
		}

		switch subResult.Status {
		case StatusFail:
			hasFail = true
		case StatusPartial:
			hasPartial = true
		case StatusPass:
			hasPass = true
		}
	}

	if allNotTested {
		return StatusNotTested
	}

	if hasFail {
		return StatusFail
	}

	if hasPartial {
		return StatusPartial
	}

	if hasPass {
		return StatusPass
	}

	return StatusNotTested
}

// identifyGaps identifies requirements with no findings (potential gaps)
func identifyGaps(results map[string]*RequirementResult) []Gap {
	gaps := make([]Gap, 0)

	for _, reqResult := range results {
		for _, subReqResult := range reqResult.SubRequirementResults {
			if subReqResult.FindingsCount == 0 {
				gaps = append(gaps, Gap{
					Requirement:    reqResult.Requirement,
					SubRequirement: subReqResult.SubRequirement,
					Reason:         "No findings detected - requirement not tested or fully compliant",
				})
			}
		}
	}

	return gaps
}

// generateRecommendations creates prioritized remediation recommendations
func generateRecommendations(results map[string]*RequirementResult) []Recommendation {
	recommendations := make([]Recommendation, 0)

	for _, reqResult := range results {
		for _, subReqResult := range reqResult.SubRequirementResults {
			if subReqResult.FindingsCount > 0 {
				rec := Recommendation{
					Requirement:     reqResult.Requirement,
					SubRequirement:  subReqResult.SubRequirement,
					ThreatCount:     subReqResult.FindingsCount,
					HighestSeverity: subReqResult.HighestSeverity,
					Action:          generateAction(reqResult.Requirement, subReqResult.SubRequirement),
				}

				// Calculate priority (1 = highest)
				rec.Priority = calculatePriority(subReqResult.HighestSeverity, subReqResult.FindingsCount)

				recommendations = append(recommendations, rec)
			}
		}
	}

	// Sort by priority
	sort.Slice(recommendations, func(i, j int) bool {
		return recommendations[i].Priority < recommendations[j].Priority
	})

	return recommendations
}

// calculatePriority calculates recommendation priority based on severity and count
func calculatePriority(severity models.ThreatSeverity, count int) int {
	basePriority := 100

	// Severity weight
	switch severity {
	case models.SeverityCritical:
		basePriority = 10
	case models.SeverityHigh:
		basePriority = 30
	case models.SeverityMedium:
		basePriority = 50
	case models.SeverityLow:
		basePriority = 70
	case models.SeverityInfo:
		basePriority = 90
	}

	// Adjust for volume (more findings = higher priority)
	if count > 10 {
		basePriority -= 10
	} else if count > 5 {
		basePriority -= 5
	}

	if basePriority < 1 {
		basePriority = 1
	}

	return basePriority
}

// generateAction generates a recommended action for a requirement
func generateAction(req Requirement, subReq SubRequirement) string {
	// Map common sub-requirements to actions
	actions := map[string]string{
		"6.2.4": "Implement input validation, output encoding, and parameterized queries to prevent injection attacks",
		"8.2.1": "Remove hardcoded credentials and implement strong authentication mechanisms",
		"8.3.1": "Implement multi-factor authentication for all CDE access",
		"3.5.1": "Encrypt all stored cardholder data using strong cryptography",
		"4.2.1": "Ensure all cardholder data transmission uses TLS 1.2+ with strong cipher suites",
		"7.2.1": "Implement role-based access control (RBAC) with least privilege principle",
		"10.2.1": "Implement comprehensive audit logging for all access to cardholder data",
		"2.2.2": "Change all vendor default passwords and remove unnecessary default accounts",
		"3.3.1": "Remove logging of sensitive authentication data (CVV, PIN, full track data)",
		"6.4.1": "Deploy WAF or implement RASP for web application protection",
		"3.6.1": "Implement secure key management with proper encryption of cryptographic keys",
	}

	if action, ok := actions[subReq.ID]; ok {
		return action
	}

	return fmt.Sprintf("Review and remediate findings for %s: %s", subReq.ID, subReq.Description)
}

// ToMarkdown generates a markdown report
func (r *ComplianceReport) ToMarkdown() string {
	var sb strings.Builder

	// Header
	sb.WriteString("# PCI DSS v4.0 Compliance Report\n\n")
	sb.WriteString(fmt.Sprintf("**Generated:** %s\n\n", r.GeneratedAt.Format("2006-01-02 15:04:05")))
	sb.WriteString("---\n\n")

	// Executive Summary
	sb.WriteString("## Executive Summary\n\n")
	
	totalReqs := len(r.RequirementResults)
	passCount := 0
	failCount := 0
	partialCount := 0
	notTestedCount := 0

	for _, result := range r.RequirementResults {
		switch result.Status {
		case StatusPass:
			passCount++
		case StatusFail:
			failCount++
		case StatusPartial:
			partialCount++
		case StatusNotTested:
			notTestedCount++
		}
	}

	sb.WriteString(fmt.Sprintf("- **Total Requirements Assessed:** %d\n", totalReqs))
	sb.WriteString(fmt.Sprintf("- **Threats Analyzed:** %d\n", r.TotalThreats))
	sb.WriteString(fmt.Sprintf("- **Total Findings:** %d\n\n", r.TotalFindings))
	
	sb.WriteString("### Compliance Status Breakdown\n\n")
	sb.WriteString(fmt.Sprintf("- ✅ **Pass:** %d (%.1f%%)\n", passCount, float64(passCount)/float64(totalReqs)*100))
	sb.WriteString(fmt.Sprintf("- ⚠️  **Partial:** %d (%.1f%%)\n", partialCount, float64(partialCount)/float64(totalReqs)*100))
	sb.WriteString(fmt.Sprintf("- ❌ **Fail:** %d (%.1f%%)\n", failCount, float64(failCount)/float64(totalReqs)*100))
	sb.WriteString(fmt.Sprintf("- ⚪ **Not Tested:** %d (%.1f%%)\n\n", notTestedCount, float64(notTestedCount)/float64(totalReqs)*100))

	// Requirements with findings
	sb.WriteString("---\n\n")
	sb.WriteString("## Detailed Findings by Requirement\n\n")

	// Sort requirements by ID
	reqIDs := make([]string, 0, len(r.RequirementResults))
	for reqID := range r.RequirementResults {
		reqIDs = append(reqIDs, reqID)
	}
	sort.Strings(reqIDs)

	for _, reqID := range reqIDs {
		result := r.RequirementResults[reqID]
		
		if result.FindingsCount == 0 {
			continue // Skip requirements with no findings
		}

		statusIcon := getStatusIcon(result.Status)
		sb.WriteString(fmt.Sprintf("### %s Requirement %s: %s\n\n", statusIcon, result.Requirement.ID, result.Requirement.Title))
		sb.WriteString(fmt.Sprintf("**Status:** %s | **Findings:** %d\n\n", result.Status, result.FindingsCount))
		sb.WriteString(fmt.Sprintf("_%s_\n\n", result.Requirement.Description))

		// Sub-requirements
		subReqIDs := make([]string, 0, len(result.SubRequirementResults))
		for subReqID := range result.SubRequirementResults {
			subReqIDs = append(subReqIDs, subReqID)
		}
		sort.Strings(subReqIDs)

		for _, subReqID := range subReqIDs {
			subResult := result.SubRequirementResults[subReqID]
			
			if subResult.FindingsCount == 0 {
				continue
			}

			subStatusIcon := getStatusIcon(subResult.Status)
			sb.WriteString(fmt.Sprintf("#### %s Requirement %s\n\n", subStatusIcon, subResult.SubRequirement.ID))
			sb.WriteString(fmt.Sprintf("**Description:** %s\n\n", subResult.SubRequirement.Description))
			sb.WriteString(fmt.Sprintf("**Findings:** %d | **Highest Severity:** %s\n\n", 
				subResult.FindingsCount, subResult.HighestSeverity))

			// List threats
			if len(subResult.Threats) > 0 {
				sb.WriteString("**Related Threats:**\n\n")
				for _, threat := range subResult.Threats {
					sb.WriteString(fmt.Sprintf("- [%s] %s\n", threat.Severity, threat.Title))
				}
				sb.WriteString("\n")
			}
		}

		sb.WriteString("---\n\n")
	}

	// Gap Analysis
	if len(r.GapAnalysis) > 0 {
		sb.WriteString("## Gap Analysis\n\n")
		sb.WriteString("The following requirements have **no findings detected**. This could indicate:\n\n")
		sb.WriteString("1. Full compliance with the requirement\n")
		sb.WriteString("2. The requirement was not tested by the threat model\n")
		sb.WriteString("3. Additional manual assessment may be needed\n\n")

		sb.WriteString("| Requirement | Sub-Requirement | Description |\n")
		sb.WriteString("|-------------|-----------------|-------------|\n")
		for _, gap := range r.GapAnalysis {
			sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", 
				gap.Requirement.ID, gap.SubRequirement.ID, gap.SubRequirement.Description))
		}
		sb.WriteString("\n")
	}

	// Recommendations
	if len(r.Recommendations) > 0 {
		sb.WriteString("---\n\n")
		sb.WriteString("## Prioritized Remediation Recommendations\n\n")
		sb.WriteString("Recommendations ordered by priority (1 = highest):\n\n")

		for i, rec := range r.Recommendations {
			if i >= 20 { // Limit to top 20
				break
			}

			sb.WriteString(fmt.Sprintf("### %d. Requirement %s (Priority: %d)\n\n", 
				i+1, rec.SubRequirement.ID, rec.Priority))
			sb.WriteString(fmt.Sprintf("**Severity:** %s | **Finding Count:** %d\n\n", 
				rec.HighestSeverity, rec.ThreatCount))
			sb.WriteString(fmt.Sprintf("**Action:** %s\n\n", rec.Action))
		}
	}

	// Footer
	sb.WriteString("---\n\n")
	sb.WriteString("## Notes\n\n")
	sb.WriteString("This report is generated from automated threat modeling and code analysis. ")
	sb.WriteString("It should be used as part of a comprehensive PCI DSS compliance assessment, ")
	sb.WriteString("not as a replacement for a qualified security assessor (QSA) audit.\n\n")
	sb.WriteString("**PCI DSS v4.0** is the current version as of this report generation.\n\n")

	return sb.String()
}

// getStatusIcon returns an icon for a requirement status
func getStatusIcon(status RequirementStatus) string {
	switch status {
	case StatusPass:
		return "✅"
	case StatusFail:
		return "❌"
	case StatusPartial:
		return "⚠️"
	case StatusNotTested:
		return "⚪"
	default:
		return "❓"
	}
}
