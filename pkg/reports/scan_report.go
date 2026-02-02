package reports

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Leathal1/TITO/v2/pkg/mapper"
	"github.com/Leathal1/TITO/v2/pkg/models"
	"github.com/Leathal1/TITO/v2/pkg/scanner"
	"github.com/Leathal1/TITO/v2/pkg/stridelm"
)

// ScanReportData holds everything needed to generate a scan report
type ScanReportData struct {
	Repository    string
	Branch        string
	Language      string
	Framework     string
	Architecture  string
	Assets        []scanner.Asset
	DataFlows     []scanner.DataFlow
	Dependencies  []scanner.Dependency
	Threats       []*models.Threat
	MappedThreats []mapper.MappedThreat
	SemgrepCount  int
}

// GenerateScanReport produces a standard threat model report in markdown
func GenerateScanReport(data *ScanReportData, outputPath string) error {
	var b strings.Builder

	now := time.Now().Format("2006-01-02 15:04 MST")

	// ── Header ──
	b.WriteString("# Threat Model Report\n\n")
	b.WriteString(fmt.Sprintf("**Generated:** %s  \n", now))
	b.WriteString(fmt.Sprintf("**Repository:** %s  \n", data.Repository))
	b.WriteString(fmt.Sprintf("**Branch:** %s  \n", data.Branch))
	b.WriteString(fmt.Sprintf("**Language:** %s  \n", data.Language))
	if data.Framework != "" {
		b.WriteString(fmt.Sprintf("**Framework:** %s  \n", data.Framework))
	}
	if data.Architecture != "" {
		b.WriteString(fmt.Sprintf("**Architecture:** %s  \n", data.Architecture))
	}
	b.WriteString("**Tool:** TITO (Threat In, Threat Out)  \n")
	b.WriteString("\n---\n\n")

	// ── Executive Summary ──
	b.WriteString("## Executive Summary\n\n")
	critCount, highCount, medCount, lowCount := countSeverities(data.MappedThreats)
	totalThreats := len(data.MappedThreats)
	b.WriteString(fmt.Sprintf("TITO identified **%d threats** across **%d assets** with **%d data flows**.\n\n",
		totalThreats, len(data.Assets), len(data.DataFlows)))

	b.WriteString("| Severity | Count |\n|----------|-------|\n")
	b.WriteString(fmt.Sprintf("| 🔴 Critical | %d |\n", critCount))
	b.WriteString(fmt.Sprintf("| 🟠 High | %d |\n", highCount))
	b.WriteString(fmt.Sprintf("| 🟡 Medium | %d |\n", medCount))
	b.WriteString(fmt.Sprintf("| 🟢 Low | %d |\n", lowCount))
	b.WriteString("\n")

	if data.SemgrepCount > 0 {
		b.WriteString(fmt.Sprintf("Semgrep SAST identified **%d** additional code-level findings.\n\n", data.SemgrepCount))
	}

	// ── 1. Assets ──
	b.WriteString("## 1. Assets\n\n")
	exposedCount := 0
	sensitiveCount := 0
	assetsByType := make(map[string][]scanner.Asset)
	for _, a := range data.Assets {
		assetsByType[string(a.Type)] = append(assetsByType[string(a.Type)], a)
		if a.Exposed {
			exposedCount++
		}
		if a.Sensitive {
			sensitiveCount++
		}
	}
	b.WriteString(fmt.Sprintf("**Total:** %d assets | **Exposed:** %d | **Sensitive:** %d\n\n",
		len(data.Assets), exposedCount, sensitiveCount))

	// Asset table by type
	b.WriteString("| Type | Count | Exposed | Sensitive |\n|------|-------|---------|----------|\n")
	type typeStat struct {
		Type      string
		Count     int
		Exposed   int
		Sensitive int
	}
	var typeStats []typeStat
	for t, assets := range assetsByType {
		ts := typeStat{Type: t, Count: len(assets)}
		for _, a := range assets {
			if a.Exposed {
				ts.Exposed++
			}
			if a.Sensitive {
				ts.Sensitive++
			}
		}
		typeStats = append(typeStats, ts)
	}
	sort.Slice(typeStats, func(i, j int) bool { return typeStats[i].Count > typeStats[j].Count })
	for _, ts := range typeStats {
		b.WriteString(fmt.Sprintf("| %s | %d | %d | %d |\n", ts.Type, ts.Count, ts.Exposed, ts.Sensitive))
	}
	b.WriteString("\n")

	// Top exposed assets with locations
	if exposedCount > 0 {
		b.WriteString("### Exposed Assets\n\n")
		b.WriteString("| Asset | Type | Location |\n|-------|------|----------|\n")
		shown := 0
		for _, a := range data.Assets {
			if a.Exposed && shown < 20 {
				loc := formatLocation(a.Location)
				b.WriteString(fmt.Sprintf("| %s | %s | %s |\n",
					truncateStr(a.Name, 50), a.Type, loc))
				shown++
			}
		}
		if exposedCount > 20 {
			b.WriteString(fmt.Sprintf("\n*...and %d more exposed assets*\n", exposedCount-20))
		}
		b.WriteString("\n")
	}

	// ── 2. Threats ──
	b.WriteString("## 2. Threats\n\n")

	// STRIDE distribution
	strideCounts := make(map[string]int)
	for _, t := range data.Threats {
		if t.StrideProfile != nil {
			cat := string(t.StrideProfile.PrimaryCategory)
			strideCounts[cat] += t.InstanceCount
			if t.InstanceCount == 0 {
				strideCounts[cat]++
			}
		}
	}
	if len(strideCounts) > 0 {
		b.WriteString("### STRIDE-LM Distribution\n\n")
		b.WriteString("| Category | Findings |\n|----------|----------|\n")
		for cat, info := range stridelm.AllCategories() {
			if count, ok := strideCounts[string(cat)]; ok {
				b.WriteString(fmt.Sprintf("| %s | %d |\n", info.FullName, count))
			}
		}
		b.WriteString("\n")
	}

	// Individual threat findings with file/line
	b.WriteString("### Findings\n\n")
	for i, mt := range data.MappedThreats {
		severityIcon := severityEmoji(mt.Threat.Severity)
		b.WriteString(fmt.Sprintf("#### %s %d. %s\n\n", severityIcon, i+1, mt.Threat.Title))
		b.WriteString(fmt.Sprintf("**Severity:** %s | **Risk Score:** %.2f\n\n",
			strings.ToUpper(string(mt.Threat.Severity)), mt.RiskScore))

		if mt.Threat.Description != "" {
			b.WriteString(fmt.Sprintf("%s\n\n", mt.Threat.Description))
		}

		if mt.Threat.StrideProfile != nil {
			info := stridelm.GetCategoryInfo(mt.Threat.StrideProfile.PrimaryCategory)
			b.WriteString(fmt.Sprintf("**STRIDE-LM:** %s — *%s*\n\n", info.FullName, info.Question))
		}

		// Affected files/locations
		if len(mt.Assets) > 0 {
			b.WriteString("**Affected Locations:**\n\n")
			b.WriteString("| File | Line | Asset | Type |\n|------|------|-------|------|\n")
			shown := 0
			seen := make(map[string]bool)
			for _, a := range mt.Assets {
				loc := fmt.Sprintf("%s:%d", a.Location.File, a.Location.Line)
				if seen[loc] || shown >= 10 {
					continue
				}
				seen[loc] = true
				b.WriteString(fmt.Sprintf("| `%s` | %d | %s | %s |\n",
					a.Location.File, a.Location.Line,
					truncateStr(a.Name, 40), a.Type))
				shown++
			}
			remaining := len(mt.Assets) - shown
			if remaining > 0 {
				b.WriteString(fmt.Sprintf("\n*...and %d more locations*\n", remaining))
			}
			b.WriteString("\n")
		}

		// Mitigations for this threat
		if len(mt.Mitigations) > 0 {
			b.WriteString("**Mitigations:**\n\n")
			seen := make(map[string]bool)
			shown := 0
			for _, m := range mt.Mitigations {
				if seen[m.Description] || shown >= 3 {
					continue
				}
				seen[m.Description] = true
				b.WriteString(fmt.Sprintf("- **[%s]** %s", m.Priority, m.Description))
				if m.Code != "" {
					b.WriteString(fmt.Sprintf("\n  ```\n  %s\n  ```", truncateStr(m.Code, 200)))
				}
				b.WriteString("\n")
				shown++
			}
			b.WriteString("\n")
		}

		b.WriteString("---\n\n")
	}

	// ── 3. Mitigating Controls ──
	b.WriteString("## 3. Mitigating Controls\n\n")
	b.WriteString("### Recommended Actions (by priority)\n\n")

	// Collect unique mitigations across all threats, ordered by priority
	type mitigEntry struct {
		Description string
		Priority    string
		Type        string
		Count       int // how many threats this applies to
	}
	mitigMap := make(map[string]*mitigEntry)
	for _, mt := range data.MappedThreats {
		for _, m := range mt.Mitigations {
			if existing, ok := mitigMap[m.Description]; ok {
				existing.Count++
			} else {
				mitigMap[m.Description] = &mitigEntry{
					Description: m.Description,
					Priority:    m.Priority,
					Type:        string(m.Type),
					Count:       1,
				}
			}
		}
	}

	var mitigList []*mitigEntry
	for _, m := range mitigMap {
		mitigList = append(mitigList, m)
	}
	// Sort: critical first, then high, then by count
	priorityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
	sort.Slice(mitigList, func(i, j int) bool {
		pi := priorityOrder[mitigList[i].Priority]
		pj := priorityOrder[mitigList[j].Priority]
		if pi != pj {
			return pi < pj
		}
		return mitigList[i].Count > mitigList[j].Count
	})

	b.WriteString("| # | Priority | Control | Applies To |\n|---|----------|---------|------------|\n")
	for i, m := range mitigList {
		pIcon := priorityIcon(m.Priority)
		b.WriteString(fmt.Sprintf("| %d | %s %s | %s | %d threats |\n",
			i+1, pIcon, m.Priority, m.Description, m.Count))
	}
	b.WriteString("\n")

	// ── Dependencies ──
	if len(data.Dependencies) > 0 {
		b.WriteString("## Dependencies\n\n")
		b.WriteString(fmt.Sprintf("**Total:** %d\n\n", len(data.Dependencies)))
		b.WriteString("| Package | Version |\n|---------|---------|\n")
		for i, d := range data.Dependencies {
			if i >= 30 {
				b.WriteString(fmt.Sprintf("\n*...and %d more*\n", len(data.Dependencies)-30))
				break
			}
			b.WriteString(fmt.Sprintf("| %s | %s |\n", d.Name, d.Version))
		}
		b.WriteString("\n")
	}

	// ── Footer ──
	b.WriteString("---\n\n")
	b.WriteString("*Generated by [TITO](https://github.com/Leathal1/TITO) — Threat In, Threat Out*  \n")
	b.WriteString(fmt.Sprintf("*Report date: %s*\n", now))

	return os.WriteFile(outputPath, []byte(b.String()), 0644)
}

// Helper functions

func countSeverities(threats []mapper.MappedThreat) (crit, high, med, low int) {
	for _, mt := range threats {
		switch mt.Threat.Severity {
		case models.SeverityCritical:
			crit++
		case models.SeverityHigh:
			high++
		case models.SeverityMedium:
			med++
		case models.SeverityLow:
			low++
		}
	}
	return
}

func formatLocation(loc scanner.Location) string {
	if loc.File == "" {
		return "-"
	}
	if loc.Line > 0 {
		return fmt.Sprintf("`%s:%d`", loc.File, loc.Line)
	}
	return fmt.Sprintf("`%s`", loc.File)
}

func severityEmoji(s models.ThreatSeverity) string {
	switch s {
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

func priorityIcon(p string) string {
	switch p {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🟢"
	default:
		return "⚪"
	}
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
