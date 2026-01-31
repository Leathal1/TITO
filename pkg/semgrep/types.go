package semgrep

// SemgrepOutput represents the JSON output from Semgrep
type SemgrepOutput struct {
	Results []Finding `json:"results"`
	Errors  []Error   `json:"errors"`
}

// Finding represents a single Semgrep finding
type Finding struct {
	CheckID string   `json:"check_id"`
	Path    string   `json:"path"`
	Start   Position `json:"start"`
	End     Position `json:"end"`
	Extra   Extra    `json:"extra"`
}

// Position represents a position in source code
type Position struct {
	Line   int `json:"line"`
	Col    int `json:"col"`
	Offset int `json:"offset"`
}

// Extra contains additional metadata about the finding
type Extra struct {
	Message     string            `json:"message"`
	Severity    string            `json:"severity"` // ERROR, WARNING, INFO
	Metadata    Metadata          `json:"metadata"`
	Lines       string            `json:"lines"`
	Fingerprint string            `json:"fingerprint"`
	IsIgnored   bool              `json:"is_ignored"`
	FixRegex    map[string]string `json:"fix_regex,omitempty"`
}

// Metadata contains rule metadata
type Metadata struct {
	Category        string   `json:"category"`
	Technology      []string `json:"technology"`
	Confidence      string   `json:"confidence"` // HIGH, MEDIUM, LOW
	Likelihood      string   `json:"likelihood"`
	Impact          string   `json:"impact"`
	Subcategory     []string `json:"subcategory"`
	OWASP           []string `json:"owasp"`
	CWE             []string `json:"cwe"`
	References      []string `json:"references"`
	License         string   `json:"license"`
	VulnerabilityClass []string `json:"vulnerability_class"`
}

// Error represents a Semgrep error
type Error struct {
	Message string `json:"message"`
	Level   string `json:"level"`
	Type    string `json:"type"`
	Path    string `json:"path,omitempty"`
}

// SeverityLevel represents severity levels
type SeverityLevel string

const (
	SeverityError   SeverityLevel = "ERROR"
	SeverityWarning SeverityLevel = "WARNING"
	SeverityInfo    SeverityLevel = "INFO"
)

// ConfidenceLevel represents confidence levels
type ConfidenceLevel string

const (
	ConfidenceHigh   ConfidenceLevel = "HIGH"
	ConfidenceMedium ConfidenceLevel = "MEDIUM"
	ConfidenceLow    ConfidenceLevel = "LOW"
)
