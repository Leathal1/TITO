package attackpath

import (
	"github.com/Leathal1/TITO/pkg/dataflow"
)

// AttackGraph represents the complete attack graph built from dataflow
type AttackGraph struct {
	Nodes       map[string]*AttackNode `json:"nodes"`
	Edges       []*AttackEdge          `json:"edges"`
	EntryPoints []string               `json:"entryPoints"`
	CrownJewels []string               `json:"crownJewels"`
}

// AttackNode wraps a dataflow node with attack-relevant metadata
type AttackNode struct {
	ID             string            `json:"id"`
	Label          string            `json:"label"`
	NodeType       dataflow.NodeType `json:"nodeType"`
	RiskLevel      dataflow.RiskLevel `json:"riskLevel"`
	Zone           string            `json:"zone"`
	Findings       []dataflow.Finding `json:"findings"`
	IsEntryPoint   bool              `json:"isEntryPoint"`
	IsCrownJewel   bool              `json:"isCrownJewel"`
	Exploitability float64           `json:"exploitability"`
}

// AttackEdge represents a possible lateral movement between nodes
type AttackEdge struct {
	Source        string  `json:"source"`
	Target        string  `json:"target"`
	Technique     string  `json:"technique"`
	Difficulty    float64 `json:"difficulty"`
	RequiredPriv  string  `json:"requiredPriv"`
	DataSensitive bool    `json:"dataSensitive"`
	Encrypted     bool    `json:"encrypted"`
	MitreID       string  `json:"mitreID"`
}

// AttackPath represents a complete attack chain from entry to crown jewel
type AttackPath struct {
	ID              string       `json:"id"`
	EntryPoint      string       `json:"entryPoint"`
	Target          string       `json:"target"`
	Steps           []AttackStep `json:"steps"`
	TotalDifficulty float64      `json:"totalDifficulty"`
	CompositeRisk   float64      `json:"compositeRisk"`
	MitreTactics    []string     `json:"mitreTactics"`
	Narrative       string       `json:"narrative"`
}

// AttackStep represents one hop in the attack path
type AttackStep struct {
	FromNode    string  `json:"fromNode"`
	ToNode      string  `json:"toNode"`
	Technique   string  `json:"technique"`
	Difficulty  float64 `json:"difficulty"`
	MitreID     string  `json:"mitreID"`
	Description string  `json:"description"`
}
