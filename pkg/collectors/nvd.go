package collectors

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Leathal1/TITO/pkg/models"
	"github.com/Leathal1/TITO/pkg/stridelm"
)

// NVDCollector collects CVE data from the National Vulnerability Database
type NVDCollector struct {
	*BaseCollector
	apiKey    string
	baseURL   string
	daysBack  int
	interval  time.Duration
	client    *http.Client
	classifier *stridelm.Classifier
}

// NewNVDCollector creates a new NVD collector
func NewNVDCollector(apiKey string, daysBack int) *NVDCollector {
	return &NVDCollector{
		BaseCollector: NewBaseCollector("NVD"),
		apiKey:        apiKey,
		baseURL:       "https://services.nvd.nist.gov/rest/json/cves/2.0",
		daysBack:      daysBack,
		interval:      6 * time.Hour, // Run every 6 hours
		client:        &http.Client{Timeout: 30 * time.Second},
		classifier:    stridelm.NewClassifier(),
	}
}

// Interval returns how often the collector should run
func (n *NVDCollector) Interval() time.Duration {
	return n.interval
}

// ShouldRun checks if enough time has passed since last run
func (n *NVDCollector) ShouldRun() bool {
	if n.lastRun.IsZero() {
		return true
	}
	return time.Since(n.lastRun) >= n.interval
}

// Collect performs the collection workflow
func (n *NVDCollector) Collect(ctx context.Context) ([]*models.Threat, error) {
	n.ClearErrors()

	// For demonstration, return mock data
	// Real implementation would call NVD API
	rawCVEs := n.getMockCVEs()

	threats := make([]*models.Threat, 0)
	for _, rawCVE := range rawCVEs {
		threat, err := n.parseCVE(rawCVE)
		if err != nil {
			n.AddError(err)
			continue
		}
		if threat != nil {
			threats = append(threats, threat)
		}
	}

	n.RecordRun()
	return threats, nil
}

// CVEData represents the structure of CVE data from NVD API
type CVEData struct {
	CVE     CVEInfo `json:"cve"`
	Metrics Metrics `json:"metrics"`
}

type CVEInfo struct {
	ID             string        `json:"id"`
	Descriptions   []Description `json:"descriptions"`
	Published      string        `json:"published"`
	LastModified   string        `json:"lastModified"`
	VulnStatus     string        `json:"vulnStatus"`
	References     []Reference   `json:"references"`
	Weaknesses     []Weakness    `json:"weaknesses"`
}

type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type Reference struct {
	URL string `json:"url"`
}

type Weakness struct {
	Description []Description `json:"description"`
}

type Metrics struct {
	CVSSMetricV31 []CVSSMetric `json:"cvssMetricV31"`
}

type CVSSMetric struct {
	CVSSData CVSSData `json:"cvssData"`
}

type CVSSData struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
	VectorString string  `json:"vectorString"`
}

// parseCVE transforms raw NVD data into a Threat object
func (n *NVDCollector) parseCVE(data CVEData) (*models.Threat, error) {
	cveID := data.CVE.ID

	// Extract description
	description := ""
	for _, desc := range data.CVE.Descriptions {
		if desc.Lang == "en" {
			description = desc.Value
			break
		}
	}

	// Extract CVSS metrics
	var severityStr string
	var vectorString string

	if len(data.Metrics.CVSSMetricV31) > 0 {
		cvssData := data.Metrics.CVSSMetricV31[0].CVSSData
		severityStr = strings.ToLower(cvssData.BaseSeverity)
		vectorString = cvssData.VectorString
	}

	// Map CVSS severity to our ThreatSeverity
	severity := n.mapSeverity(severityStr)

	// Extract CWE IDs
	cweIDs := n.extractCWEIDs(data.CVE.Weaknesses)

	// Parse CVSS vector for context
	context := n.parseCVSSVector(vectorString, cveID)

	// Create threat indicator
	now := time.Now()
	indicator := models.ThreatIndicator{
		ID:          fmt.Sprintf("ind-%s-%d", cveID, now.Unix()),
		Type:        models.IndicatorCVE,
		Value:       cveID,
		Description: description,
		Confidence:  1.0, // NVD is authoritative
		FirstSeen:   now,
		LastSeen:    now,
		Tags:        []string{"nvd", "cve"},
		Source:      "NVD",
	}

	// Classify using STRIDE-LM
	classificationText := cveID + " " + description
	strideProfile := n.classifier.Classify(stridelm.ClassificationInput{
		Text:   classificationText,
		CVEID:  cveID,
		CWEIDs: cweIDs,
	})

	// Extract references
	references := make([]string, 0)
	for _, ref := range data.CVE.References {
		references = append(references, ref.URL)
	}

	// Create threat
	publishedAt := n.parseTimestamp(data.CVE.Published)
	threat := &models.Threat{
		ID:            fmt.Sprintf("threat-%s-%d", cveID, now.Unix()),
		Title:         fmt.Sprintf("%s: %s", cveID, n.truncate(description, 100)),
		Description:   description,
		Severity:      severity,
		StrideProfile: strideProfile,
		Indicators:    []models.ThreatIndicator{indicator},
		Context:       context,
		DiscoveredAt:  now,
		PublishedAt:   &publishedAt,
		UpdatedAt:     now,
		References:    references,
		CVEIDs:        []string{cveID},
		Tags:          []string{string(severity), "cve", "nvd"},
		SourceFeeds:   []string{"NVD"},
	}

	// Generate recommendations
	threat.RecommendedActions = n.generateRecommendations(strideProfile, severity, cveID)

	// Calculate priority
	threat.UpdatePriority()

	return threat, nil
}

// mapSeverity maps CVSS severity string to ThreatSeverity
func (n *NVDCollector) mapSeverity(severityStr string) models.ThreatSeverity {
	switch severityStr {
	case "critical":
		return models.SeverityCritical
	case "high":
		return models.SeverityHigh
	case "medium":
		return models.SeverityMedium
	case "low":
		return models.SeverityLow
	case "none":
		return models.SeverityInfo
	default:
		return models.SeverityMedium
	}
}

// extractCWEIDs extracts CWE IDs from weakness data
func (n *NVDCollector) extractCWEIDs(weaknesses []Weakness) []int {
	cweIDs := make([]int, 0)
	cwePattern := regexp.MustCompile(`CWE-(\d+)`)

	for _, weakness := range weaknesses {
		for _, desc := range weakness.Description {
			matches := cwePattern.FindStringSubmatch(desc.Value)
			if len(matches) > 1 {
				var cweID int
				fmt.Sscanf(matches[1], "%d", &cweID)
				cweIDs = append(cweIDs, cweID)
			}
		}
	}

	return cweIDs
}

// parseCVSSVector parses CVSS vector string into ThreatContext
func (n *NVDCollector) parseCVSSVector(vectorString, cveID string) models.ThreatContext {
	context := models.ThreatContext{
		ExploitationStatus: models.ExploitationUnknown,
	}

	if vectorString == "" {
		return context
	}

	// Parse vector components
	components := make(map[string]string)
	parts := strings.Split(vectorString, "/")
	for _, part := range parts {
		if strings.Contains(part, ":") {
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				components[kv[0]] = kv[1]
			}
		}
	}

	// Attack Vector (AV)
	if av, ok := components["AV"]; ok {
		switch av {
		case "N": // Network
			context.ExposureLevel = "internet"
			context.AffectsKnownAssets = true
		case "A": // Adjacent Network
			context.ExposureLevel = "internal"
		case "L", "P": // Local or Physical
			context.ExposureLevel = "isolated"
		}
	}

	// Attack Complexity (AC)
	if ac, ok := components["AC"]; ok {
		if ac == "L" {
			context.AttackComplexity = "low"
		} else {
			context.AttackComplexity = "high"
		}
	}

	// Privileges Required (PR)
	if pr, ok := components["PR"]; ok {
		switch pr {
		case "N":
			context.PrivilegesRequired = "none"
		case "L":
			context.PrivilegesRequired = "low"
		case "H":
			context.PrivilegesRequired = "high"
		}
	}

	// User Interaction (UI)
	if ui, ok := components["UI"]; ok {
		context.UserInteractionRequired = ui == "R" // Required
	}

	return context
}

// generateRecommendations generates actionable recommendations
func (n *NVDCollector) generateRecommendations(profile *stridelm.Profile, severity models.ThreatSeverity, cveID string) []string {
	recommendations := make([]string, 0)

	// Urgency based on severity
	if severity == models.SeverityCritical || severity == models.SeverityHigh {
		recommendations = append(recommendations,
			"URGENT: Prioritize patching immediately. This is a critical vulnerability.",
			"Check for indicators of compromise in logs from the last 90 days.",
		)
	}

	// STRIDE-LM specific recommendations
	if profile != nil {
		categoryInfo := stridelm.GetCategoryInfo(profile.PrimaryCategory)
		// Add top 2 mitigation strategies
		if len(categoryInfo.MitigationStrategies) >= 2 {
			recommendations = append(recommendations, categoryInfo.MitigationStrategies[0:2]...)
		}
	}

	// Generic CVE actions
	recommendations = append(recommendations,
		fmt.Sprintf("Review NVD advisory for %s for full details.", cveID),
		"Validate patches in staging before production deployment.",
	)

	return recommendations
}

// parseTimestamp parses NVD timestamp format
func (n *NVDCollector) parseTimestamp(timestampStr string) time.Time {
	if timestampStr == "" {
		return time.Now()
	}

	// Try parsing ISO8601 format
	t, err := time.Parse(time.RFC3339, timestampStr)
	if err != nil {
		return time.Now()
	}
	return t
}

// truncate truncates a string to the specified length
func (n *NVDCollector) truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// getMockCVEs returns mock CVE data for demonstration
func (n *NVDCollector) getMockCVEs() []CVEData {
	return []CVEData{
		{
			CVE: CVEInfo{
				ID: "CVE-2024-1234",
				Descriptions: []Description{
					{
						Lang:  "en",
						Value: "SQL injection vulnerability in Apache Example 2.4.x allows remote attackers to execute arbitrary SQL commands via crafted input.",
					},
				},
				Published:    time.Now().Add(-24 * time.Hour).Format(time.RFC3339),
				LastModified: time.Now().Format(time.RFC3339),
				VulnStatus:   "Analyzed",
				References: []Reference{
					{URL: "https://example.com/advisory/CVE-2024-1234"},
				},
				Weaknesses: []Weakness{
					{
						Description: []Description{
							{Value: "CWE-89"},
						},
					},
				},
			},
			Metrics: Metrics{
				CVSSMetricV31: []CVSSMetric{
					{
						CVSSData: CVSSData{
							BaseScore:    9.8,
							BaseSeverity: "CRITICAL",
							VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
						},
					},
				},
			},
		},
		{
			CVE: CVEInfo{
				ID: "CVE-2024-5678",
				Descriptions: []Description{
					{
						Lang:  "en",
						Value: "Authentication bypass in Login Manager allows unauthorized access",
					},
				},
				Published:    time.Now().Add(-12 * time.Hour).Format(time.RFC3339),
				LastModified: time.Now().Format(time.RFC3339),
				VulnStatus:   "Analyzed",
				References: []Reference{
					{URL: "https://example.com/advisory/CVE-2024-5678"},
				},
				Weaknesses: []Weakness{
					{
						Description: []Description{
							{Value: "CWE-287"},
						},
					},
				},
			},
			Metrics: Metrics{
				CVSSMetricV31: []CVSSMetric{
					{
						CVSSData: CVSSData{
							BaseScore:    8.1,
							BaseSeverity: "HIGH",
							VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
						},
					},
				},
			},
		},
	}
}

// fetchFromAPI would be the real implementation fetching from NVD API
func (n *NVDCollector) fetchFromAPI(ctx context.Context) ([]CVEData, error) {
	// Real implementation would:
	// 1. Construct query with date range
	// 2. Make HTTP request with API key
	// 3. Handle pagination
	// 4. Parse JSON response
	// 5. Implement rate limiting
	return nil, fmt.Errorf("not implemented")
}
