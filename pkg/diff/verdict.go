package diff

import (
	"fmt"

	"github.com/Leathal1/TITO/pkg/models"
)

// DetermineVerdict evaluates the diff and returns a verdict and reason
func DetermineVerdict(diff *DiffResult, config VerdictConfig) (string, string) {
	// Check for critical threats first
	criticalCount := 0
	for _, threat := range diff.AddedThreats {
		if threat.Severity == models.SeverityCritical {
			criticalCount++
		}
	}

	if criticalCount > 0 && config.FailOnCritical {
		return "FAIL", fmt.Sprintf("%d new critical threat(s) detected", criticalCount)
	}

	// Check for high-severity threats
	highCount := 0
	for _, threat := range diff.AddedThreats {
		if threat.Severity == models.SeverityHigh {
			highCount++
		}
	}

	if highCount > 0 && config.FailOnHigh {
		return "FAIL", fmt.Sprintf("%d new high-severity threat(s) detected", highCount)
	}

	// Check risk increase
	riskIncreased := diff.RiskDelta.HeadMaxRisk > diff.RiskDelta.BaseMaxRisk

	if riskIncreased && config.FailOnRiskIncrease {
		return "FAIL", fmt.Sprintf("Risk increased from %.2f to %.2f",
			diff.RiskDelta.BaseMaxRisk*10, diff.RiskDelta.HeadMaxRisk*10)
	}

	// Check max risk threshold (skip if threshold is unset/zero)
	if config.MaxRiskThreshold > 0 && diff.RiskDelta.HeadMaxRisk > config.MaxRiskThreshold {
		return "FAIL", fmt.Sprintf("Risk score %.2f exceeds threshold %.2f",
			diff.RiskDelta.HeadMaxRisk*10, config.MaxRiskThreshold*10)
	}

	// Check risk increase percentage
	if config.RiskIncreasePercent > 0 && diff.RiskDelta.BaseMaxRisk > 0 {
		percentIncrease := (diff.RiskDelta.HeadMaxRisk - diff.RiskDelta.BaseMaxRisk) / diff.RiskDelta.BaseMaxRisk
		if percentIncrease > config.RiskIncreasePercent {
			return "FAIL", fmt.Sprintf("Risk increased by %.1f%% (threshold: %.1f%%)",
				percentIncrease*100, config.RiskIncreasePercent*100)
		}
	}

	// WARN conditions
	if highCount > 0 && config.WarnOnHigh {
		return "WARN", fmt.Sprintf("%d new high-severity threat(s) detected", highCount)
	}

	if riskIncreased && config.WarnOnRiskIncrease {
		return "WARN", fmt.Sprintf("Risk increased from %.2f to %.2f",
			diff.RiskDelta.BaseMaxRisk*10, diff.RiskDelta.HeadMaxRisk*10)
	}

	// Check if any new threats at all
	if len(diff.AddedThreats) > 0 {
		return "WARN", fmt.Sprintf("%d new threat(s) detected", len(diff.AddedThreats))
	}

	// Check if new attack paths
	if len(diff.AddedPaths) > 0 {
		return "WARN", fmt.Sprintf("%d new attack path(s) detected", len(diff.AddedPaths))
	}

	// PASS conditions
	if len(diff.RemovedThreats) > 0 && !riskIncreased {
		return "PASS", fmt.Sprintf("%d threat(s) resolved, risk stable at %.2f",
			len(diff.RemovedThreats), diff.RiskDelta.HeadMaxRisk*10)
	}

	if diff.RiskDelta.RiskDirection == "decreased" {
		return "PASS", fmt.Sprintf("Risk decreased from %.2f to %.2f",
			diff.RiskDelta.BaseMaxRisk*10, diff.RiskDelta.HeadMaxRisk*10)
	}

	if diff.Summary.TotalChanges == 0 {
		return "PASS", "No changes detected"
	}

	// Default: PASS with stable risk
	return "PASS", fmt.Sprintf("No new threats detected. Risk stable at %.2f",
		diff.RiskDelta.HeadMaxRisk*10)
}

// VerdictToExitCode converts a verdict to a CLI exit code
func VerdictToExitCode(verdict string) int {
	switch verdict {
	case "PASS":
		return 0
	case "WARN":
		return 1
	case "FAIL":
		return 2
	default:
		return 1
	}
}

// VerdictEmoji returns an emoji for the verdict
func VerdictEmoji(verdict string) string {
	switch verdict {
	case "PASS":
		return "✅"
	case "WARN":
		return "⚠️"
	case "FAIL":
		return "❌"
	default:
		return "❓"
	}
}
