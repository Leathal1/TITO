package dataflow

// DiagramData represents the complete data flow diagram
type DiagramData struct {
	Nodes          []Node          `json:"nodes"`
	Edges          []Edge          `json:"edges"`
	TrustBoundaries []TrustBoundary `json:"trustBoundaries"`
	Metadata       Metadata        `json:"metadata"`
}

// Node represents a component in the system
type Node struct {
	ID          string   `json:"id"`
	Label       string   `json:"label"`
	Type        NodeType `json:"type"`
	RiskLevel   RiskLevel `json:"riskLevel"`
	Threats     []string `json:"threats"`     // Threat IDs
	Findings    []Finding `json:"findings"`    // Associated findings
	Description string   `json:"description"`
	Technology  string   `json:"technology"`
}

// NodeType represents the type of node
type NodeType string

const (
	NodeService    NodeType = "service"
	NodeDatabase   NodeType = "database"
	NodeAPI        NodeType = "api"
	NodeAgent      NodeType = "agent"
	NodeExternal   NodeType = "external"
	NodeCache      NodeType = "cache"
	NodeQueue      NodeType = "queue"
	NodeUser       NodeType = "user"
)

// RiskLevel represents the risk level of a component
type RiskLevel string

const (
	RiskCritical RiskLevel = "critical"
	RiskHigh     RiskLevel = "high"
	RiskMedium   RiskLevel = "medium"
	RiskLow      RiskLevel = "low"
)

// Edge represents a data flow between nodes
type Edge struct {
	ID          string   `json:"id"`
	Source      string   `json:"source"`
	Target      string   `json:"target"`
	Label       string   `json:"label"`
	DataType    string   `json:"dataType"`
	Sensitive   bool     `json:"sensitive"`
	Encrypted   bool     `json:"encrypted"`
	Protocols   []string `json:"protocols"`
	Threats     []string `json:"threats"`
}

// TrustBoundary represents a security boundary
type TrustBoundary struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Nodes []string `json:"nodes"` // Node IDs within this boundary
	Color string   `json:"color"`
	Zone  string   `json:"zone"` // internet, dmz, internal, secure
}

// Finding represents a threat or vulnerability finding
type Finding struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	STRIDE      string `json:"stride"`
	MAESTRO     string `json:"maestro"`
	ATTACKIDs   []string `json:"attackIds"`
	Mitigations []string `json:"mitigations"`
	Source      string `json:"source"` // STRIDE-LM, MAESTRO, Semgrep, etc.
}

// Metadata contains diagram metadata
type Metadata struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Generated   string `json:"generated"`
	Repository  string `json:"repository"`
	Branch      string `json:"branch"`
	TotalNodes  int    `json:"totalNodes"`
	TotalEdges  int    `json:"totalEdges"`
	TotalThreats int   `json:"totalThreats"`
}

// GetRiskColor returns the color for a risk level
func (r RiskLevel) GetColor() string {
	switch r {
	case RiskCritical:
		return "#ff4444" // Red
	case RiskHigh:
		return "#ff8c00" // Orange
	case RiskMedium:
		return "#ffd700" // Yellow
	case RiskLow:
		return "#00d4aa" // Green/Cyan
	default:
		return "#888888" // Gray
	}
}

// GetNodeIcon returns the icon for a node type
func (n NodeType) GetIcon() string {
	switch n {
	case NodeService:
		return "⚙️"
	case NodeDatabase:
		return "🗄️"
	case NodeAPI:
		return "🔌"
	case NodeAgent:
		return "🤖"
	case NodeExternal:
		return "🌐"
	case NodeCache:
		return "💾"
	case NodeQueue:
		return "📬"
	case NodeUser:
		return "👤"
	default:
		return "📦"
	}
}
