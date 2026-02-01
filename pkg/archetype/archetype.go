package archetype

// ArchType represents the primary architecture type of an application
type ArchType string

const (
	ArchMonolith        ArchType = "monolith"
	ArchMicroservices   ArchType = "microservices"
	ArchServerless      ArchType = "serverless"
	ArchCLI             ArchType = "cli"
	ArchLibrary         ArchType = "library"
	ArchAPIService      ArchType = "api-service"
	ArchWebApp          ArchType = "web-app"
	ArchMobileBackend   ArchType = "mobile-backend"
	ArchDataPipeline    ArchType = "data-pipeline"
	ArchAIML            ArchType = "ai-ml"
	ArchUnknown         ArchType = "unknown"
)

// String returns the human-readable name of the architecture type
func (a ArchType) String() string {
	switch a {
	case ArchMonolith:
		return "Monolith"
	case ArchMicroservices:
		return "Microservices"
	case ArchServerless:
		return "Serverless"
	case ArchCLI:
		return "CLI Tool"
	case ArchLibrary:
		return "Library/SDK"
	case ArchAPIService:
		return "API Service"
	case ArchWebApp:
		return "Web Application"
	case ArchMobileBackend:
		return "Mobile Backend"
	case ArchDataPipeline:
		return "Data Pipeline"
	case ArchAIML:
		return "AI/ML Service"
	case ArchUnknown:
		return "Unknown"
	default:
		return string(a)
	}
}

// SignalType represents the type of detection signal
type SignalType string

const (
	SignalProjectStructure SignalType = "project-structure"
	SignalDependency       SignalType = "dependency"
	SignalFilePattern      SignalType = "file-pattern"
	SignalCodePattern      SignalType = "code-pattern"
	SignalConfig           SignalType = "config"
)

// Signal represents evidence found during architecture detection
type Signal struct {
	Type        SignalType  `json:"type"`
	Description string      `json:"description"`
	Evidence    string      `json:"evidence"`
	Weight      float64     `json:"weight"`      // 0.0 to 1.0
	ArchType    ArchType    `json:"arch_type"`   // Which architecture this signals
}

// ArchProfile represents the detected architecture profile of an application
type ArchProfile struct {
	PrimaryType    ArchType   `json:"primary_type"`
	SecondaryTypes []ArchType `json:"secondary_types"`
	Confidence     float64    `json:"confidence"`      // 0.0 to 1.0
	Signals        []Signal   `json:"signals"`
	Description    string     `json:"description"`
}

// AddSignal adds a detection signal and recalculates confidence
func (p *ArchProfile) AddSignal(signal Signal) {
	p.Signals = append(p.Signals, signal)
}

// CalculateConfidence calculates overall confidence based on signals
func (p *ArchProfile) CalculateConfidence() float64 {
	if len(p.Signals) == 0 {
		return 0.0
	}

	// Calculate confidence based on weighted votes
	totalVotes := make(map[ArchType]float64)
	totalWeight := 0.0

	for _, signal := range p.Signals {
		totalVotes[signal.ArchType] += signal.Weight
		totalWeight += signal.Weight
	}

	if totalWeight == 0 {
		return 0.0
	}

	// Confidence is the proportion of votes for primary type
	primaryVotes := totalVotes[p.PrimaryType]
	confidence := primaryVotes / totalWeight

	if confidence > 1.0 {
		return 1.0
	}
	return confidence
}

// GenerateDescription generates a human-readable description of the architecture
func (p *ArchProfile) GenerateDescription(language, framework string) string {
	desc := p.PrimaryType.String()
	
	if language != "" && language != "unknown" {
		desc = language + " " + desc
	}
	
	if framework != "" && framework != "unknown" && framework != "stdlib" {
		desc += " using " + framework
	}
	
	// Add notable signals (deduplicate)
	featureMap := make(map[string]bool)
	var features []string
	for _, signal := range p.Signals {
		if signal.Weight >= 0.7 && signal.Type == SignalDependency {
			if !featureMap[signal.Evidence] {
				featureMap[signal.Evidence] = true
				features = append(features, signal.Evidence)
			}
		}
	}
	
	if len(features) > 0 {
		if len(features) <= 3 {
			desc += " with " + joinFeatures(features)
		} else {
			desc += " with " + joinFeatures(features[:3]) + " and more"
		}
	}
	
	return desc
}

// joinFeatures joins feature strings with proper grammar
func joinFeatures(features []string) string {
	if len(features) == 0 {
		return ""
	}
	if len(features) == 1 {
		return features[0]
	}
	if len(features) == 2 {
		return features[0] + " and " + features[1]
	}
	
	result := ""
	for i, f := range features {
		if i == len(features)-1 {
			result += "and " + f
		} else if i > 0 {
			result += ", " + f
		} else {
			result += f
		}
	}
	return result
}
