package archetype

// ThreatAdjustment represents architecture-specific threat considerations
type ThreatAdjustment struct {
	AdditionalThreats []string  `json:"additional_threats"`
	RiskMultipliers   map[string]float64 `json:"risk_multipliers"` // Category -> multiplier
	Recommendations   []string  `json:"recommendations"`
}

// GetThreatAdjustments returns architecture-specific threat adjustments
func GetThreatAdjustments(profile *ArchProfile) *ThreatAdjustment {
	if profile == nil {
		return &ThreatAdjustment{
			AdditionalThreats: []string{},
			RiskMultipliers:   make(map[string]float64),
			Recommendations:   []string{},
		}
	}

	adjustment := &ThreatAdjustment{
		AdditionalThreats: []string{},
		RiskMultipliers:   make(map[string]float64),
		Recommendations:   []string{},
	}

	switch profile.PrimaryType {
	case ArchMicroservices:
		adjustment.AdditionalThreats = append(adjustment.AdditionalThreats,
			"Service-to-service authentication bypass",
			"API gateway misconfiguration",
			"Service mesh security gaps",
			"East-west traffic interception",
			"Distributed tracing data exposure",
			"Service discovery poisoning",
			"Circuit breaker manipulation",
			"Cascading failures from single service compromise",
		)
		adjustment.RiskMultipliers["Tampering"] = 1.3  // More attack surface
		adjustment.RiskMultipliers["Elevation of Privilege"] = 1.2
		adjustment.Recommendations = append(adjustment.Recommendations,
			"Implement mutual TLS (mTLS) for service-to-service communication",
			"Use service mesh with zero-trust policies",
			"Enforce API gateway authentication and rate limiting",
			"Implement distributed tracing with sensitive data redaction",
			"Monitor east-west traffic for anomalies",
			"Use network policies to restrict inter-service communication",
		)

	case ArchServerless:
		adjustment.AdditionalThreats = append(adjustment.AdditionalThreats,
			"Cold start injection attacks",
			"Event injection and manipulation",
			"Over-permissive IAM roles",
			"Function timeout exploitation",
			"Shared execution environment escape",
			"Function poisoning via dependencies",
			"Secrets exposure in environment variables",
			"Denial of wallet (resource exhaustion)",
		)
		adjustment.RiskMultipliers["Spoofing"] = 1.4  // Event sources
		adjustment.RiskMultipliers["Elevation of Privilege"] = 1.5  // IAM misconfig common
		adjustment.Recommendations = append(adjustment.Recommendations,
			"Apply principle of least privilege to IAM roles",
			"Validate all event sources and payloads",
			"Use secrets manager instead of environment variables",
			"Implement function-level access controls",
			"Monitor function invocation patterns for anomalies",
			"Set aggressive timeout and memory limits",
			"Use VPC for sensitive functions",
		)

	case ArchMonolith:
		adjustment.AdditionalThreats = append(adjustment.AdditionalThreats,
			"Single point of failure - full system compromise",
			"Large blast radius from any vulnerability",
			"Privilege escalation within monolith",
			"Shared database access from all code paths",
			"Difficult to implement least privilege",
			"Session hijacking affects entire application",
		)
		adjustment.RiskMultipliers["Information Disclosure"] = 1.2
		adjustment.RiskMultipliers["Denial of Service"] = 1.3  // Single point of failure
		adjustment.Recommendations = append(adjustment.Recommendations,
			"Implement strong internal access controls",
			"Use principle of least privilege at database level",
			"Deploy behind load balancer with health checks",
			"Implement comprehensive logging and monitoring",
			"Consider modular architecture for future decomposition",
			"Use feature flags to limit blast radius",
		)

	case ArchCLI:
		adjustment.AdditionalThreats = append(adjustment.AdditionalThreats,
			"Command injection via arguments",
			"Path traversal in file operations",
			"Credential theft from config files",
			"Environment variable manipulation",
			"Binary tampering and supply chain attacks",
			"Insecure update mechanisms",
		)
		adjustment.RiskMultipliers["Tampering"] = 1.2
		adjustment.RiskMultipliers["Elevation of Privilege"] = 1.1
		adjustment.Recommendations = append(adjustment.Recommendations,
			"Validate and sanitize all command-line inputs",
			"Use absolute paths and avoid shell execution",
			"Store credentials in OS-provided secure storage",
			"Sign binaries and verify signatures on updates",
			"Implement secure auto-update with verification",
			"Minimize required privileges",
		)

	case ArchLibrary:
		adjustment.AdditionalThreats = append(adjustment.AdditionalThreats,
			"Supply chain attacks via dependency",
			"API misuse by downstream consumers",
			"Transitive dependency vulnerabilities",
			"Namespace/typosquatting attacks",
			"Version confusion attacks",
			"Insecure defaults propagated to consumers",
		)
		adjustment.RiskMultipliers["Tampering"] = 1.4  // Supply chain
		adjustment.Recommendations = append(adjustment.Recommendations,
			"Implement secure defaults and fail-safe APIs",
			"Provide clear security documentation",
			"Minimize dependencies and audit transitive deps",
			"Use dependency pinning and lock files",
			"Sign published packages",
			"Implement semver strictly and communicate breaking changes",
		)

	case ArchAPIService:
		adjustment.AdditionalThreats = append(adjustment.AdditionalThreats,
			"API authentication bypass",
			"Broken object-level authorization (BOLA)",
			"Mass assignment vulnerabilities",
			"API rate limiting bypass",
			"GraphQL query complexity attacks",
			"API versioning vulnerabilities",
			"CORS misconfiguration",
		)
		adjustment.RiskMultipliers["Spoofing"] = 1.3
		adjustment.RiskMultipliers["Information Disclosure"] = 1.2
		adjustment.Recommendations = append(adjustment.Recommendations,
			"Implement OAuth 2.0 or API key authentication",
			"Enforce object-level authorization checks",
			"Use allow-lists for API input fields",
			"Implement rate limiting per user/IP",
			"Validate and limit query complexity",
			"Use API gateway for centralized security",
		)

	case ArchWebApp:
		adjustment.AdditionalThreats = append(adjustment.AdditionalThreats,
			"Cross-site scripting (XSS)",
			"Cross-site request forgery (CSRF)",
			"Clickjacking",
			"Open redirects",
			"Server-side template injection",
			"Frontend secrets exposure",
			"Client-side storage attacks",
		)
		adjustment.RiskMultipliers["Spoofing"] = 1.2
		adjustment.RiskMultipliers["Tampering"] = 1.2
		adjustment.Recommendations = append(adjustment.Recommendations,
			"Implement Content Security Policy (CSP)",
			"Use CSRF tokens for state-changing operations",
			"Set X-Frame-Options and HTTPS headers",
			"Sanitize all user input before rendering",
			"Never store secrets in frontend code",
			"Use HTTP-only and Secure flags on cookies",
		)

	case ArchMobileBackend:
		adjustment.AdditionalThreats = append(adjustment.AdditionalThreats,
			"Mobile app reverse engineering",
			"API key extraction from mobile apps",
			"Push notification injection",
			"Device token theft",
			"Certificate pinning bypass",
			"Jailbreak/root detection bypass",
			"Deep link hijacking",
		)
		adjustment.RiskMultipliers["Spoofing"] = 1.3
		adjustment.RiskMultipliers["Information Disclosure"] = 1.2
		adjustment.Recommendations = append(adjustment.Recommendations,
			"Implement certificate pinning in mobile app",
			"Use device attestation APIs",
			"Validate push notification recipients",
			"Implement rate limiting per device",
			"Use backend-driven feature flags",
			"Monitor for rooted/jailbroken devices",
		)

	case ArchDataPipeline:
		adjustment.AdditionalThreats = append(adjustment.AdditionalThreats,
			"Data poisoning attacks",
			"Pipeline injection",
			"ETL logic bypass",
			"Unauthorized data access during processing",
			"Data exfiltration via pipeline logs",
			"Schema manipulation attacks",
			"Workflow orchestration tampering",
		)
		adjustment.RiskMultipliers["Tampering"] = 1.4
		adjustment.RiskMultipliers["Information Disclosure"] = 1.3
		adjustment.Recommendations = append(adjustment.Recommendations,
			"Validate and sanitize all input data",
			"Implement data lineage tracking",
			"Encrypt data at rest and in transit",
			"Use least privilege for pipeline service accounts",
			"Implement data quality checks and alerts",
			"Restrict access to pipeline orchestration",
		)

	case ArchAIML:
		adjustment.AdditionalThreats = append(adjustment.AdditionalThreats,
			"Prompt injection attacks",
			"Model inversion and extraction",
			"Training data poisoning",
			"Adversarial input attacks",
			"Model backdoors",
			"Sensitive data leakage from training data",
			"RAG context injection",
			"LLM jailbreaking",
		)
		adjustment.RiskMultipliers["Information Disclosure"] = 1.5  // Model memorization
		adjustment.RiskMultipliers["Tampering"] = 1.3
		adjustment.Recommendations = append(adjustment.Recommendations,
			"Implement MAESTRO layer security controls",
			"Validate and sanitize all prompts and inputs",
			"Use content filtering and output validation",
			"Implement rate limiting on model inference",
			"Monitor for adversarial patterns",
			"Sanitize training data and implement differential privacy",
			"Use guardrails for LLM outputs",
		)
	}

	// Add secondary type adjustments
	for _, secondary := range profile.SecondaryTypes {
		switch secondary {
		case ArchAIML:
			if profile.PrimaryType != ArchAIML {
				adjustment.AdditionalThreats = append(adjustment.AdditionalThreats,
					"ML model security - see AI/ML architecture threats",
				)
			}
		case ArchDataPipeline:
			if profile.PrimaryType != ArchDataPipeline {
				adjustment.AdditionalThreats = append(adjustment.AdditionalThreats,
					"Data pipeline security - validate data flows",
				)
			}
		}
	}

	return adjustment
}

// GetArchitectureSpecificControls returns recommended security controls
func GetArchitectureSpecificControls(profile *ArchProfile) []string {
	if profile == nil {
		return []string{}
	}

	controls := []string{}

	switch profile.PrimaryType {
	case ArchMicroservices:
		controls = append(controls,
			"Service Mesh (Istio, Linkerd, Consul)",
			"API Gateway (Kong, Ambassador, Envoy)",
			"Distributed Tracing (Jaeger, Zipkin)",
			"Service Registry (Consul, Eureka)",
			"Secrets Management (Vault, Sealed Secrets)",
		)
	case ArchServerless:
		controls = append(controls,
			"IAM Policy Analyzer",
			"Function-level firewalls",
			"Secrets Manager integration",
			"CloudWatch/CloudTrail monitoring",
			"VPC isolation for sensitive functions",
		)
	case ArchAIML:
		controls = append(controls,
			"Prompt injection filters",
			"Output content filtering",
			"Model access controls",
			"Differential privacy",
			"Adversarial robustness testing",
		)
	}

	return controls
}
