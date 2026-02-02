package format

import (
	"fmt"
	"strings"

	"github.com/Leathal1/TITO/v2/pkg/diff"
	"github.com/Leathal1/TITO/v2/pkg/models"
)

// FormatMarkdown generates a GitHub-friendly markdown summary
func FormatMarkdown(d *diff.DiffResult) string {
	var b strings.Builder

	// Header
	b.WriteString("## 🛡️ TITO Threat Model Delta\n\n")

	// Risk summary
	riskEmoji := getRiskDirectionEmoji(d.RiskDelta.RiskDirection)
	verdictEmoji := diff.VerdictEmoji(d.Summary.RiskVerdict)

	b.WriteString(fmt.Sprintf("**Risk: %s %s** (%.1f → %.1f) | Verdict: %s %s\n\n",
		riskEmoji,
		strings.ToUpper(d.RiskDelta.RiskDirection),
		d.RiskDelta.BaseMaxRisk*10,
		d.RiskDelta.HeadMaxRisk*10,
		verdictEmoji,
		d.Summary.RiskVerdict))

	// Changes table
	b.WriteString("### Changes\n")
	b.WriteString("| Category | Added | Removed | Modified |\n")
	b.WriteString("|----------|-------|---------|----------|\n")

	b.WriteString(fmt.Sprintf("| Assets | +%d | -%d | %d |\n",
		len(d.AddedAssets), len(d.RemovedAssets), len(d.ModifiedAssets)))

	b.WriteString(fmt.Sprintf("| Threats | +%d | -%d | - |\n",
		len(d.AddedThreats), len(d.RemovedThreats)))

	b.WriteString(fmt.Sprintf("| Data Flows | +%d | -%d | - |\n",
		len(d.AddedFlows), len(d.RemovedFlows)))

	b.WriteString(fmt.Sprintf("| Attack Paths | +%d | -%d | - |\n",
		len(d.AddedPaths), len(d.RemovedPaths)))

	updatedDepsStr := ""
	if len(d.UpdatedDeps) > 0 {
		updatedDepsStr = fmt.Sprintf("%d updated", len(d.UpdatedDeps))
	} else {
		updatedDepsStr = "-"
	}
	b.WriteString(fmt.Sprintf("| Dependencies | +%d | -%d | %s |\n",
		len(d.AddedDeps), len(d.RemovedDeps), updatedDepsStr))

	b.WriteString("\n")

	// New Threats
	if len(d.AddedThreats) > 0 {
		b.WriteString(fmt.Sprintf("### ⚠️ New Threats (%d)\n", len(d.AddedThreats)))
		for _, threat := range d.AddedThreats {
			emoji := getSeverityEmoji(threat.Severity)
			b.WriteString(fmt.Sprintf("- %s **%s** [%s]",
				emoji,
				threat.Title,
				strings.ToUpper(string(threat.Severity))))

			if threat.Description != "" {
				b.WriteString(fmt.Sprintf(" — %s", truncate(threat.Description, 100)))
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	// New Attack Paths
	if len(d.AddedPaths) > 0 {
		b.WriteString(fmt.Sprintf("### 🆕 New Attack Paths (%d)\n", len(d.AddedPaths)))
		for i, path := range d.AddedPaths {
			if i >= 5 {
				b.WriteString(fmt.Sprintf("_...and %d more_\n", len(d.AddedPaths)-5))
				break
			}

			b.WriteString(fmt.Sprintf("- **%s → %s** (Risk: %.1f/10) — %d steps, %s difficulty\n",
				path.EntryPoint,
				path.Target,
				path.CompositeRisk,
				len(path.Steps),
				getDifficultyLevel(path.TotalDifficulty)))
		}
		b.WriteString("\n")
	}

	// Resolved Threats
	if len(d.RemovedThreats) > 0 {
		b.WriteString(fmt.Sprintf("### ✅ Resolved Threats (%d)\n", len(d.RemovedThreats)))
		for _, threat := range d.RemovedThreats {
			b.WriteString(fmt.Sprintf("- %s [%s]\n", threat.Title, strings.ToUpper(string(threat.Severity))))
		}
		b.WriteString("\n")
	} else if len(d.AddedThreats) > 0 {
		b.WriteString("### ✅ Resolved Threats (0)\n")
		b.WriteString("_No threats were resolved in this change_\n\n")
	}

	// New Assets (only show if significant)
	if len(d.AddedAssets) > 0 && len(d.AddedAssets) <= 10 {
		b.WriteString(fmt.Sprintf("### 📊 New Assets (%d)\n", len(d.AddedAssets)))
		for _, asset := range d.AddedAssets {
			flags := make([]string, 0)
			if asset.Exposed {
				flags = append(flags, "**exposed**")
			}
			if asset.Sensitive {
				flags = append(flags, "**sensitive**")
			}

			flagStr := ""
			if len(flags) > 0 {
				flagStr = " — " + strings.Join(flags, ", ")
			}

			b.WriteString(fmt.Sprintf("- `%s` %s (%s:%d)%s\n",
				asset.Type,
				asset.Name,
				asset.Location.File,
				asset.Location.Line,
				flagStr))
		}
		b.WriteString("\n")
	} else if len(d.AddedAssets) > 10 {
		b.WriteString(fmt.Sprintf("### 📊 New Assets (%d)\n", len(d.AddedAssets)))
		b.WriteString("_Too many to display. Run `tito scan` for full details._\n\n")
	}

	// Modified Assets (only show if critical changes)
	criticalModifications := 0
	for _, assetDiff := range d.ModifiedAssets {
		for _, change := range assetDiff.Changes {
			if strings.Contains(strings.ToLower(change), "exposed") ||
				strings.Contains(strings.ToLower(change), "sensitivity") {
				criticalModifications++
				break
			}
		}
	}

	if criticalModifications > 0 {
		b.WriteString(fmt.Sprintf("### 🔄 Modified Assets (%d critical changes)\n", criticalModifications))
		count := 0
		for _, assetDiff := range d.ModifiedAssets {
			isCritical := false
			for _, change := range assetDiff.Changes {
				if strings.Contains(strings.ToLower(change), "exposed") ||
					strings.Contains(strings.ToLower(change), "sensitivity") {
					isCritical = true
					break
				}
			}

			if isCritical {
				count++
				if count > 5 {
					b.WriteString(fmt.Sprintf("_...and %d more_\n", criticalModifications-5))
					break
				}

				b.WriteString(fmt.Sprintf("- `%s` %s: %s\n",
					assetDiff.After.Type,
					assetDiff.After.Name,
					strings.Join(assetDiff.Changes, ", ")))
			}
		}
		b.WriteString("\n")
	}

	// Updated Dependencies
	if len(d.UpdatedDeps) > 0 {
		b.WriteString(fmt.Sprintf("### 📦 Updated Dependencies (%d)\n", len(d.UpdatedDeps)))
		for i, dep := range d.UpdatedDeps {
			if i >= 10 {
				b.WriteString(fmt.Sprintf("_...and %d more_\n", len(d.UpdatedDeps)-10))
				break
			}
			b.WriteString(fmt.Sprintf("- %s: %s → %s\n", dep.Name, dep.OldVersion, dep.NewVersion))
		}
		b.WriteString("\n")
	}

	// Footer
	b.WriteString("---\n")
	b.WriteString("*Generated by [TITO](https://github.com/Leathal1/TITO) • Threat model diffing for every PR*\n")

	return b.String()
}

// Helper functions

func getSeverityEmoji(severity models.ThreatSeverity) string {
	switch severity {
	case models.SeverityCritical:
		return "🔴"
	case models.SeverityHigh:
		return "🟠"
	case models.SeverityMedium:
		return "🟡"
	case models.SeverityLow:
		return "🟢"
	default:
		return "⚪"
	}
}

func getRiskDirectionEmoji(direction string) string {
	switch direction {
	case "increased":
		return "⬆️"
	case "decreased":
		return "⬇️"
	case "unchanged":
		return "➡️"
	default:
		return "❓"
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

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
