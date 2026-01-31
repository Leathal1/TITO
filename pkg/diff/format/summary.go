package format

import (
	"fmt"

	"github.com/Leathal1/TITO/pkg/diff"
)

// FormatSummary generates a one-line summary for CI output
func FormatSummary(d *diff.DiffResult) string {
	verdict := d.Summary.RiskVerdict
	emoji := diff.VerdictEmoji(verdict)

	switch verdict {
	case "PASS":
		if len(d.RemovedThreats) > 0 {
			return fmt.Sprintf("%s PASS: %d threat(s) resolved. Risk stable at %.1f",
				emoji, len(d.RemovedThreats), d.RiskDelta.HeadMaxRisk*10)
		}
		if d.RiskDelta.RiskDirection == "decreased" {
			return fmt.Sprintf("%s PASS: Risk decreased %.1f → %.1f",
				emoji, d.RiskDelta.BaseMaxRisk*10, d.RiskDelta.HeadMaxRisk*10)
		}
		return fmt.Sprintf("%s PASS: No new threats. Risk stable at %.1f",
			emoji, d.RiskDelta.HeadMaxRisk*10)

	case "WARN":
		if d.Summary.NewHighSeverity > 0 {
			return fmt.Sprintf("%s WARN: +%d new high-severity threat(s). Risk: %.1f → %.1f",
				emoji, d.Summary.NewHighSeverity,
				d.RiskDelta.BaseMaxRisk*10, d.RiskDelta.HeadMaxRisk*10)
		}
		if d.RiskDelta.RiskDirection == "increased" {
			return fmt.Sprintf("%s WARN: Risk increased %.1f → %.1f",
				emoji, d.RiskDelta.BaseMaxRisk*10, d.RiskDelta.HeadMaxRisk*10)
		}
		return fmt.Sprintf("%s WARN: +%d new threat(s). Risk: %.1f",
			emoji, len(d.AddedThreats), d.RiskDelta.HeadMaxRisk*10)

	case "FAIL":
		if d.Summary.VerdictReason != "" {
			return fmt.Sprintf("%s FAIL: %s", emoji, d.Summary.VerdictReason)
		}
		return fmt.Sprintf("%s FAIL: Critical security regression detected. Risk: %.1f → %.1f",
			emoji, d.RiskDelta.BaseMaxRisk*10, d.RiskDelta.HeadMaxRisk*10)

	default:
		return fmt.Sprintf("%s UNKNOWN: Unable to determine verdict", emoji)
	}
}
