package mitre

import (
	"github.com/Leathal1/TITO/v2/pkg/maestro"
	"github.com/Leathal1/TITO/v2/pkg/stridelm"
)

// Mapping represents a mapping between threat categories and ATT&CK techniques
type Mapping struct {
	TechniqueID string
	Confidence  float64 // 0.0 to 1.0
	Reason      string
}

// Mapper maps STRIDE-LM categories and MAESTRO layers to ATT&CK techniques
type Mapper struct {
	techniques []Technique
}

// NewMapper creates a new MITRE ATT&CK mapper
func NewMapper() *Mapper {
	return &Mapper{
		techniques: AllTechniques(),
	}
}

// MapSTRIDELM maps STRIDE-LM categories to ATT&CK techniques
func (m *Mapper) MapSTRIDELM(category stridelm.Category, confidence float64) []Mapping {
	mappings := make([]Mapping, 0)

	switch category {
	case stridelm.Spoofing:
		// Spoofing relates to credential access and initial access
		mappings = append(mappings, Mapping{
			TechniqueID: "T1078", // Valid Accounts
			Confidence:  confidence * 0.9,
			Reason:      "Spoofing often involves using valid credentials",
		})
		mappings = append(mappings, Mapping{
			TechniqueID: "T1110", // Brute Force
			Confidence:  confidence * 0.7,
			Reason:      "Credential attacks may involve brute force",
		})
		mappings = append(mappings, Mapping{
			TechniqueID: "T1566", // Phishing
			Confidence:  confidence * 0.8,
			Reason:      "Phishing is a common spoofing technique",
		})

	case stridelm.Tampering:
		// Tampering relates to data manipulation and defense evasion
		mappings = append(mappings, Mapping{
			TechniqueID: "T1565", // Data Manipulation
			Confidence:  confidence * 0.9,
			Reason:      "Tampering involves data manipulation",
		})
		mappings = append(mappings, Mapping{
			TechniqueID: "T1190", // Exploit Public-Facing Application
			Confidence:  confidence * 0.7,
			Reason:      "Exploitation often leads to tampering",
		})
		mappings = append(mappings, Mapping{
			TechniqueID: "T1027", // Obfuscated Files or Information
			Confidence:  confidence * 0.6,
			Reason:      "Tampering may involve obfuscation",
		})

	case stridelm.Repudiation:
		// Repudiation relates to indicator removal and defense evasion
		mappings = append(mappings, Mapping{
			TechniqueID: "T1070", // Indicator Removal
			Confidence:  confidence * 0.95,
			Reason:      "Repudiation involves removing evidence",
		})
		mappings = append(mappings, Mapping{
			TechniqueID: "T1562", // Impair Defenses
			Confidence:  confidence * 0.7,
			Reason:      "May disable logging or monitoring",
		})

	case stridelm.InfoDisclosure:
		// Information Disclosure relates to collection and exfiltration
		mappings = append(mappings, Mapping{
			TechniqueID: "T1005", // Data from Local System
			Confidence:  confidence * 0.8,
			Reason:      "Information disclosure involves data collection",
		})
		mappings = append(mappings, Mapping{
			TechniqueID: "T1041", // Exfiltration Over C2 Channel
			Confidence:  confidence * 0.7,
			Reason:      "Data may be exfiltrated",
		})
		mappings = append(mappings, Mapping{
			TechniqueID: "T1567", // Exfiltration Over Web Service
			Confidence:  confidence * 0.7,
			Reason:      "Data may be exfiltrated via web services",
		})
		mappings = append(mappings, Mapping{
			TechniqueID: "T1083", // File and Directory Discovery
			Confidence:  confidence * 0.6,
			Reason:      "May involve discovering sensitive files",
		})

	case stridelm.DenialOfService:
		// DoS relates to impact
		mappings = append(mappings, Mapping{
			TechniqueID: "T1499", // Endpoint Denial of Service
			Confidence:  confidence * 0.95,
			Reason:      "Direct DoS attack",
		})
		mappings = append(mappings, Mapping{
			TechniqueID: "T1490", // Inhibit System Recovery
			Confidence:  confidence * 0.6,
			Reason:      "May prevent recovery from DoS",
		})

	case stridelm.Elevation:
		// Elevation relates to privilege escalation
		mappings = append(mappings, Mapping{
			TechniqueID: "T1068", // Exploitation for Privilege Escalation
			Confidence:  confidence * 0.9,
			Reason:      "Elevation involves privilege escalation",
		})
		mappings = append(mappings, Mapping{
			TechniqueID: "T1078", // Valid Accounts
			Confidence:  confidence * 0.7,
			Reason:      "May use valid accounts with elevated privileges",
		})

	case stridelm.LateralMovement:
		// Lateral Movement directly maps
		mappings = append(mappings, Mapping{
			TechniqueID: "T1021", // Remote Services
			Confidence:  confidence * 0.9,
			Reason:      "Lateral movement via remote services",
		})
		mappings = append(mappings, Mapping{
			TechniqueID: "T1550", // Use Alternate Authentication Material
			Confidence:  confidence * 0.8,
			Reason:      "May use tokens for lateral movement",
		})
		mappings = append(mappings, Mapping{
			TechniqueID: "T1087", // Account Discovery
			Confidence:  confidence * 0.6,
			Reason:      "Discovery before lateral movement",
		})

	case stridelm.Malware:
		// Malware relates to execution, persistence, and C2
		mappings = append(mappings, Mapping{
			TechniqueID: "T1059", // Command and Scripting Interpreter
			Confidence:  confidence * 0.8,
			Reason:      "Malware execution via scripting",
		})
		mappings = append(mappings, Mapping{
			TechniqueID: "T1543", // Create or Modify System Process
			Confidence:  confidence * 0.8,
			Reason:      "Malware persistence",
		})
		mappings = append(mappings, Mapping{
			TechniqueID: "T1071", // Application Layer Protocol
			Confidence:  confidence * 0.7,
			Reason:      "Malware C2 communication",
		})
		mappings = append(mappings, Mapping{
			TechniqueID: "T1105", // Ingress Tool Transfer
			Confidence:  confidence * 0.7,
			Reason:      "Malware delivery",
		})
	}

	return mappings
}

// MapMAESTRO maps MAESTRO layers to ATT&CK techniques
func (m *Mapper) MapMAESTRO(layer maestro.Layer, confidence float64) []Mapping {
	mappings := make([]Mapping, 0)

	switch layer {
	case maestro.FoundationModels:
		// Foundation model attacks often involve initial access and execution
		mappings = append(mappings, Mapping{
			TechniqueID: "T1190", // Exploit Public-Facing Application
			Confidence:  confidence * 0.8,
			Reason:      "Exploiting LLM APIs and interfaces",
		})
		mappings = append(mappings, Mapping{
			TechniqueID: "T1059", // Command and Scripting Interpreter
			Confidence:  confidence * 0.7,
			Reason:      "Prompt injection leading to code execution",
		})
		mappings = append(mappings, Mapping{
			TechniqueID: "T1005", // Data from Local System
			Confidence:  confidence * 0.6,
			Reason:      "Training data extraction",
		})

	case maestro.DataKnowledge:
		// RAG poisoning relates to data manipulation
		mappings = append(mappings, Mapping{
			TechniqueID: "T1565", // Data Manipulation
			Confidence:  confidence * 0.9,
			Reason:      "RAG poisoning and knowledge base manipulation",
		})
		mappings = append(mappings, Mapping{
			TechniqueID: "T1083", // File and Directory Discovery
			Confidence:  confidence * 0.6,
			Reason:      "Discovering knowledge sources",
		})
		mappings = append(mappings, Mapping{
			TechniqueID: "T1005", // Data from Local System
			Confidence:  confidence * 0.7,
			Reason:      "Accessing vector databases",
		})

	case maestro.AgentFrameworks:
		// Framework exploits involve execution and persistence
		mappings = append(mappings, Mapping{
			TechniqueID: "T1059", // Command and Scripting Interpreter
			Confidence:  confidence * 0.9,
			Reason:      "Exploiting agent tool calling for code execution",
		})
		mappings = append(mappings, Mapping{
			TechniqueID: "T1203", // Exploitation for Client Execution
			Confidence:  confidence * 0.7,
			Reason:      "Framework vulnerabilities",
		})
		mappings = append(mappings, Mapping{
			TechniqueID: "T1068", // Exploitation for Privilege Escalation
			Confidence:  confidence * 0.6,
			Reason:      "Agent privilege escalation",
		})

	case maestro.ToolingIntegration:
		// Tool poisoning relates to credential access and lateral movement
		mappings = append(mappings, Mapping{
			TechniqueID: "T1555", // Credentials from Password Stores
			Confidence:  confidence * 0.9,
			Reason:      "Stealing API keys and credentials from tools",
		})
		mappings = append(mappings, Mapping{
			TechniqueID: "T1078", // Valid Accounts
			Confidence:  confidence * 0.8,
			Reason:      "Using stolen credentials",
		})
		mappings = append(mappings, Mapping{
			TechniqueID: "T1021", // Remote Services
			Confidence:  confidence * 0.7,
			Reason:      "Abusing tool integrations for access",
		})

	case maestro.AgentCommunication:
		// Inter-agent attacks relate to lateral movement and C2
		mappings = append(mappings, Mapping{
			TechniqueID: "T1021", // Remote Services
			Confidence:  confidence * 0.8,
			Reason:      "Agent-to-agent communication exploitation",
		})
		mappings = append(mappings, Mapping{
			TechniqueID: "T1550", // Use Alternate Authentication Material
			Confidence:  confidence * 0.7,
			Reason:      "Agent impersonation",
		})
		mappings = append(mappings, Mapping{
			TechniqueID: "T1071", // Application Layer Protocol
			Confidence:  confidence * 0.6,
			Reason:      "Inter-agent protocol manipulation",
		})

	case maestro.DeploymentInfra:
		// Infrastructure attacks relate to privilege escalation and persistence
		mappings = append(mappings, Mapping{
			TechniqueID: "T1068", // Exploitation for Privilege Escalation
			Confidence:  confidence * 0.9,
			Reason:      "Container escape and sandbox bypass",
		})
		mappings = append(mappings, Mapping{
			TechniqueID: "T1499", // Endpoint Denial of Service
			Confidence:  confidence * 0.8,
			Reason:      "Resource exhaustion",
		})
		mappings = append(mappings, Mapping{
			TechniqueID: "T1543", // Create or Modify System Process
			Confidence:  confidence * 0.7,
			Reason:      "Persistence in deployment environment",
		})

	case maestro.EcosystemGovernance:
		// Governance failures relate to defense evasion and impact
		mappings = append(mappings, Mapping{
			TechniqueID: "T1070", // Indicator Removal
			Confidence:  confidence * 0.8,
			Reason:      "Audit trail manipulation",
		})
		mappings = append(mappings, Mapping{
			TechniqueID: "T1562", // Impair Defenses
			Confidence:  confidence * 0.7,
			Reason:      "Bypassing compliance controls",
		})
		mappings = append(mappings, Mapping{
			TechniqueID: "T1565", // Data Manipulation
			Confidence:  confidence * 0.6,
			Reason:      "Manipulating audit logs",
		})
	}

	return mappings
}

// EnrichThreat enriches a threat with ATT&CK mappings based on both STRIDE-LM and MAESTRO
func (m *Mapper) EnrichThreat(strideProfile *stridelm.Profile, maestroProfile *maestro.Profile) map[string]Mapping {
	allMappings := make(map[string]Mapping)

	// Map STRIDE-LM categories
	if strideProfile != nil {
		// Primary category
		strideMappings := m.MapSTRIDELM(strideProfile.PrimaryCategory, 
			strideProfile.ConfidenceScores[strideProfile.PrimaryCategory])
		for _, mapping := range strideMappings {
			if existing, ok := allMappings[mapping.TechniqueID]; ok {
				// Keep the higher confidence
				if mapping.Confidence > existing.Confidence {
					allMappings[mapping.TechniqueID] = mapping
				}
			} else {
				allMappings[mapping.TechniqueID] = mapping
			}
		}

		// Secondary categories
		for _, category := range strideProfile.SecondaryCategories {
			strideMappings := m.MapSTRIDELM(category, 
				strideProfile.ConfidenceScores[category] * 0.7) // Lower weight for secondary
			for _, mapping := range strideMappings {
				if existing, ok := allMappings[mapping.TechniqueID]; ok {
					if mapping.Confidence > existing.Confidence {
						allMappings[mapping.TechniqueID] = mapping
					}
				} else {
					allMappings[mapping.TechniqueID] = mapping
				}
			}
		}
	}

	// Map MAESTRO layers
	if maestroProfile != nil {
		// Primary layer
		maestroMappings := m.MapMAESTRO(maestroProfile.PrimaryLayer, 
			maestroProfile.ConfidenceScores[maestroProfile.PrimaryLayer])
		for _, mapping := range maestroMappings {
			if existing, ok := allMappings[mapping.TechniqueID]; ok {
				if mapping.Confidence > existing.Confidence {
					allMappings[mapping.TechniqueID] = mapping
				}
			} else {
				allMappings[mapping.TechniqueID] = mapping
			}
		}

		// Secondary layers
		for _, layer := range maestroProfile.SecondaryLayers {
			maestroMappings := m.MapMAESTRO(layer, 
				maestroProfile.ConfidenceScores[layer] * 0.7) // Lower weight for secondary
			for _, mapping := range maestroMappings {
				if existing, ok := allMappings[mapping.TechniqueID]; ok {
					if mapping.Confidence > existing.Confidence {
						allMappings[mapping.TechniqueID] = mapping
					}
				} else {
					allMappings[mapping.TechniqueID] = mapping
				}
			}
		}
	}

	return allMappings
}

// GetTechniqueDetails returns full technique details for mappings
func (m *Mapper) GetTechniqueDetails(mappings map[string]Mapping) []Technique {
	techniques := make([]Technique, 0)
	for techniqueID := range mappings {
		tech := GetTechniqueByID(techniqueID)
		if tech != nil {
			techniques = append(techniques, *tech)
		}
	}
	return techniques
}
