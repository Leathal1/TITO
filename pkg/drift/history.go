package drift

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Leathal1/TITO/pkg/scan"
)

// ScanHistory manages historical scan data for trend analysis
type ScanHistory struct {
	historyDir string
}

// NewScanHistory creates a new scan history manager
func NewScanHistory() *ScanHistory {
	homeDir, _ := os.UserHomeDir()
	historyDir := filepath.Join(homeDir, ".tito", "history")
	
	// Ensure history directory exists
	os.MkdirAll(historyDir, 0755)
	
	return &ScanHistory{
		historyDir: historyDir,
	}
}

// SaveScan saves a scan result to history with timestamp
func (sh *ScanHistory) SaveScan(scanResult *scan.ScanResult) error {
	// Generate filename with timestamp
	timestamp := time.Now().Format("2006-01-02-150405")
	filename := fmt.Sprintf("%s.json", timestamp)
	historyPath := filepath.Join(sh.historyDir, filename)
	
	if err := scan.SaveResult(scanResult, historyPath); err != nil {
		return fmt.Errorf("failed to save scan to history: %w", err)
	}
	
	return nil
}

// GetHistory retrieves scan results from the last N days
func (sh *ScanHistory) GetHistory(days int) ([]*scan.ScanResult, error) {
	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
	
	entries, err := os.ReadDir(sh.historyDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []*scan.ScanResult{}, nil
		}
		return nil, fmt.Errorf("failed to read history directory: %w", err)
	}
	
	scans := make([]*scan.ScanResult, 0)
	
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		
		// Parse timestamp from filename (YYYY-MM-DD-HHMMSS.json)
		name := entry.Name()
		name = name[:len(name)-5] // Remove .json
		
		timestamp, err := time.Parse("2006-01-02-150405", name)
		if err != nil {
			// Skip files with invalid timestamp format
			continue
		}
		
		// Filter by cutoff date
		if timestamp.Before(cutoff) {
			continue
		}
		
		// Load scan result
		scanPath := filepath.Join(sh.historyDir, entry.Name())
		scanResult, err := scan.LoadResult(scanPath)
		if err != nil {
			// Skip invalid scan files
			continue
		}
		
		scans = append(scans, scanResult)
	}
	
	// Sort by timestamp (oldest first)
	sort.Slice(scans, func(i, j int) bool {
		return scans[i].Timestamp.Before(scans[j].Timestamp)
	})
	
	return scans, nil
}

// GetLatestScan retrieves the most recent scan from history
func (sh *ScanHistory) GetLatestScan() (*scan.ScanResult, error) {
	entries, err := os.ReadDir(sh.historyDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no scan history found")
		}
		return nil, fmt.Errorf("failed to read history directory: %w", err)
	}
	
	if len(entries) == 0 {
		return nil, fmt.Errorf("no scan history found")
	}
	
	// Find most recent file by timestamp
	var latestFile string
	var latestTime time.Time
	
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		
		name := entry.Name()
		name = name[:len(name)-5] // Remove .json
		
		timestamp, err := time.Parse("2006-01-02-150405", name)
		if err != nil {
			continue
		}
		
		if latestFile == "" || timestamp.After(latestTime) {
			latestFile = entry.Name()
			latestTime = timestamp
		}
	}
	
	if latestFile == "" {
		return nil, fmt.Errorf("no valid scan files found in history")
	}
	
	scanPath := filepath.Join(sh.historyDir, latestFile)
	return scan.LoadResult(scanPath)
}

// TrendData represents risk trend data over time
type TrendData struct {
	Timestamps      []time.Time `json:"timestamps"`
	MaxRiskScores   []float64   `json:"maxRiskScores"`
	AvgRiskScores   []float64   `json:"avgRiskScores"`
	CriticalCounts  []int       `json:"criticalCounts"`
	HighCounts      []int       `json:"highCounts"`
	TotalThreatCounts []int     `json:"totalThreatCounts"`
	
	// Overall trend direction
	Direction       string      `json:"direction"` // "improving", "stable", "degrading"
	PercentChange   float64     `json:"percentChange"` // % change from oldest to newest
}

// GetTrend analyzes historical scans and returns trend data
func (sh *ScanHistory) GetTrend(days int) (*TrendData, error) {
	scans, err := sh.GetHistory(days)
	if err != nil {
		return nil, err
	}
	
	if len(scans) == 0 {
		return nil, fmt.Errorf("no scan history available for trend analysis")
	}
	
	trend := &TrendData{
		Timestamps:        make([]time.Time, len(scans)),
		MaxRiskScores:     make([]float64, len(scans)),
		AvgRiskScores:     make([]float64, len(scans)),
		CriticalCounts:    make([]int, len(scans)),
		HighCounts:        make([]int, len(scans)),
		TotalThreatCounts: make([]int, len(scans)),
	}
	
	for i, s := range scans {
		trend.Timestamps[i] = s.Timestamp
		trend.MaxRiskScores[i] = s.Stats.MaxRiskScore
		trend.AvgRiskScores[i] = s.Stats.AvgRiskScore
		trend.CriticalCounts[i] = s.Stats.CriticalThreats
		trend.HighCounts[i] = s.Stats.HighThreats
		trend.TotalThreatCounts[i] = s.Stats.TotalThreats
	}
	
	// Determine trend direction
	if len(scans) >= 2 {
		oldestRisk := scans[0].Stats.MaxRiskScore
		newestRisk := scans[len(scans)-1].Stats.MaxRiskScore
		
		delta := newestRisk - oldestRisk
		
		if oldestRisk > 0 {
			trend.PercentChange = (delta / oldestRisk) * 100
		}
		
		// Threshold for "stable" is ±10%
		if delta > 0.1 || trend.PercentChange > 10 {
			trend.Direction = "degrading"
		} else if delta < -0.1 || trend.PercentChange < -10 {
			trend.Direction = "improving"
		} else {
			trend.Direction = "stable"
		}
	} else {
		trend.Direction = "insufficient data"
	}
	
	return trend, nil
}

// PrintTrend prints a user-friendly trend report
func PrintTrend(trend *TrendData) {
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════")
	fmt.Println("        TITO Security Posture Trend")
	fmt.Println("═══════════════════════════════════════════════")
	fmt.Println()
	
	// Overall trend
	trendEmoji := map[string]string{
		"improving":         "📈",
		"stable":            "➡️",
		"degrading":         "📉",
		"insufficient data": "❓",
	}
	
	emoji := trendEmoji[trend.Direction]
	fmt.Printf("%s Overall Trend: %s", emoji, trend.Direction)
	
	if trend.PercentChange != 0 {
		changeSign := "+"
		if trend.PercentChange < 0 {
			changeSign = ""
		}
		fmt.Printf(" (%s%.1f%%)", changeSign, trend.PercentChange)
	}
	fmt.Println()
	fmt.Println()
	
	// Data points summary
	fmt.Printf("📊 Analysis Period: %d scans over %d days\n", 
		len(trend.Timestamps), 
		int(trend.Timestamps[len(trend.Timestamps)-1].Sub(trend.Timestamps[0]).Hours()/24))
	fmt.Println()
	
	// Risk score trend
	fmt.Println("Risk Score Trend:")
	oldestRisk := trend.MaxRiskScores[0]
	newestRisk := trend.MaxRiskScores[len(trend.MaxRiskScores)-1]
	fmt.Printf("  Oldest: %.2f → Newest: %.2f", oldestRisk, newestRisk)
	
	if newestRisk > oldestRisk {
		fmt.Printf(" (↑ %.2f)\n", newestRisk-oldestRisk)
	} else if newestRisk < oldestRisk {
		fmt.Printf(" (↓ %.2f)\n", oldestRisk-newestRisk)
	} else {
		fmt.Println(" (unchanged)")
	}
	fmt.Println()
	
	// Threat count trend
	fmt.Println("Threat Count Trend:")
	oldestTotal := trend.TotalThreatCounts[0]
	newestTotal := trend.TotalThreatCounts[len(trend.TotalThreatCounts)-1]
	fmt.Printf("  Total Threats:    %d → %d", oldestTotal, newestTotal)
	if newestTotal > oldestTotal {
		fmt.Printf(" (↑ %d)\n", newestTotal-oldestTotal)
	} else if newestTotal < oldestTotal {
		fmt.Printf(" (↓ %d)\n", oldestTotal-newestTotal)
	} else {
		fmt.Println(" (unchanged)")
	}
	
	oldestCritical := trend.CriticalCounts[0]
	newestCritical := trend.CriticalCounts[len(trend.CriticalCounts)-1]
	fmt.Printf("  Critical Threats: %d → %d", oldestCritical, newestCritical)
	if newestCritical > oldestCritical {
		fmt.Printf(" (↑ %d)\n", newestCritical-oldestCritical)
	} else if newestCritical < oldestCritical {
		fmt.Printf(" (↓ %d)\n", oldestCritical-newestCritical)
	} else {
		fmt.Println(" (unchanged)")
	}
	
	oldestHigh := trend.HighCounts[0]
	newestHigh := trend.HighCounts[len(trend.HighCounts)-1]
	fmt.Printf("  High Threats:     %d → %d", oldestHigh, newestHigh)
	if newestHigh > oldestHigh {
		fmt.Printf(" (↑ %d)\n", newestHigh-oldestHigh)
	} else if newestHigh < oldestHigh {
		fmt.Printf(" (↓ %d)\n", oldestHigh-newestHigh)
	} else {
		fmt.Println(" (unchanged)")
	}
	fmt.Println()
	
	// Historical data points (last 5)
	fmt.Println("Recent Scan History:")
	startIdx := 0
	if len(trend.Timestamps) > 5 {
		startIdx = len(trend.Timestamps) - 5
	}
	
	for i := startIdx; i < len(trend.Timestamps); i++ {
		fmt.Printf("  %s | Risk: %.2f | Critical: %d | High: %d | Total: %d\n",
			trend.Timestamps[i].Format("2006-01-02 15:04"),
			trend.MaxRiskScores[i],
			trend.CriticalCounts[i],
			trend.HighCounts[i],
			trend.TotalThreatCounts[i])
	}
	fmt.Println()
	
	// Recommendation
	fmt.Println("💡 Recommendation:")
	if trend.Direction == "degrading" {
		fmt.Println("   Security posture is degrading. Investigate recent changes")
		fmt.Println("   and address new threats before they become incidents.")
	} else if trend.Direction == "improving" {
		fmt.Println("   Security posture is improving. Keep up the good work!")
		fmt.Println("   Continue monitoring to maintain this trend.")
	} else if trend.Direction == "stable" {
		fmt.Println("   Security posture is stable. Maintain current practices")
		fmt.Println("   and continue regular scanning.")
	} else {
		fmt.Println("   Not enough historical data for trend analysis.")
		fmt.Println("   Run more scans over time to establish a baseline.")
	}
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════")
	fmt.Println()
}

// CleanupOldScans removes scan history older than N days
func (sh *ScanHistory) CleanupOldScans(days int) (int, error) {
	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
	
	entries, err := os.ReadDir(sh.historyDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("failed to read history directory: %w", err)
	}
	
	removed := 0
	
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		
		name := entry.Name()
		name = name[:len(name)-5] // Remove .json
		
		timestamp, err := time.Parse("2006-01-02-150405", name)
		if err != nil {
			continue
		}
		
		if timestamp.Before(cutoff) {
			scanPath := filepath.Join(sh.historyDir, entry.Name())
			if err := os.Remove(scanPath); err != nil {
				continue // Skip files we can't remove
			}
			removed++
		}
	}
	
	return removed, nil
}

// CountHistoricalScans returns the total number of scans in history
func (sh *ScanHistory) CountHistoricalScans() (int, error) {
	entries, err := os.ReadDir(sh.historyDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("failed to read history directory: %w", err)
	}
	
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			count++
		}
	}
	
	return count, nil
}
