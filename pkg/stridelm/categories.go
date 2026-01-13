package stridelm

// Category represents a STRIDE-LM threat category
type Category string

const (
	Spoofing          Category = "S"
	Tampering         Category = "T"
	Repudiation       Category = "R"
	InfoDisclosure    Category = "I"
	DenialOfService   Category = "D"
	Elevation         Category = "E"
	LateralMovement   Category = "L"
	Malware           Category = "M"
)

// CategoryInfo holds metadata about a STRIDE-LM category
type CategoryInfo struct {
	Code               Category
	FullName           string
	Question           string
	Description        string
	ImpactAreas        []string
	DetectionStrategies []string
	MitigationStrategies []string
	Keywords           []string
	CWEIDs             []int
}

// AllCategories returns all STRIDE-LM categories with their metadata
func AllCategories() map[Category]CategoryInfo {
	return map[Category]CategoryInfo{
		Spoofing: {
			Code:     Spoofing,
			FullName: "Spoofing",
			Question: "Who are you, really?",
			Description: "Identity is the new perimeter. Credential leaks, auth bypasses, " +
				"token forgery. The attacker wearing your employee's face.",
			ImpactAreas: []string{"Authentication", "Identity", "Access Control", "Trust"},
			DetectionStrategies: []string{
				"Monitor authentication failures and anomalies",
				"Track credential usage patterns",
				"Validate token integrity and issuance",
				"Correlate identity across systems",
			},
			MitigationStrategies: []string{
				"Implement MFA across all systems",
				"Use hardware security keys where possible",
				"Enforce certificate-based authentication",
				"Implement passwordless authentication",
			},
			Keywords: []string{
				"authentication", "credential", "identity", "token", "session",
				"phishing", "impersonation", "auth bypass", "spoofing", "forgery",
				"oauth", "saml", "jwt", "password", "login", "username",
			},
			CWEIDs: []int{287, 290, 294, 295, 306, 307, 346, 384, 522, 798},
		},
		Tampering: {
			Code:     Tampering,
			FullName: "Tampering",
			Question: "Can I trust what I'm seeing?",
			Description: "Data integrity is assumed until it isn't. Supply chain attacks, " +
				"injection, MITM. The code you deployed isn't the code running.",
			ImpactAreas: []string{"Data Integrity", "Code Integrity", "Supply Chain", "Trust"},
			DetectionStrategies: []string{
				"Implement integrity checks and signatures",
				"Monitor for unexpected code/data changes",
				"Verify supply chain provenance",
				"Use runtime application self-protection",
			},
			MitigationStrategies: []string{
				"Sign all code and data",
				"Implement software bill of materials (SBOM)",
				"Use secure channels for all transfers",
				"Deploy runtime integrity monitoring",
			},
			Keywords: []string{
				"injection", "tampering", "modification", "supply chain", "mitm",
				"integrity", "sql injection", "xss", "csrf", "code injection",
				"path traversal", "file upload", "deserialization", "backdoor",
			},
			CWEIDs: []int{20, 74, 78, 79, 89, 94, 352, 502, 611, 913},
		},
		Repudiation: {
			Code:     Repudiation,
			FullName: "Repudiation",
			Question: "Did that really happen?",
			Description: "Logs are your memory; memory can be erased. Audit gaps, " +
				"timestamp manipulation. The attack you can't prove occurred.",
			ImpactAreas: []string{"Audit", "Logging", "Forensics", "Accountability"},
			DetectionStrategies: []string{
				"Ensure centralized, immutable logging",
				"Monitor for log deletion or manipulation",
				"Implement clock synchronization",
				"Create audit trails for critical actions",
			},
			MitigationStrategies: []string{
				"Use write-once logging systems",
				"Implement centralized SIEM",
				"Enable audit logs for all critical systems",
				"Use blockchain for critical audit trails",
			},
			Keywords: []string{
				"logging", "audit", "repudiation", "forensics", "timestamp",
				"log injection", "audit bypass", "accountability", "traceability",
			},
			CWEIDs: []int{117, 532, 778},
		},
		InfoDisclosure: {
			Code:     InfoDisclosure,
			FullName: "Information Disclosure",
			Question: "What's escaping?",
			Description: "Secrets have gravity; they fall toward exposure. Breaches, " +
				"misconfigs, verbose errors. The data you forgot you were storing.",
			ImpactAreas: []string{"Confidentiality", "Privacy", "Secrets Management", "Data Protection"},
			DetectionStrategies: []string{
				"Monitor outbound data transfers",
				"Implement DLP and secrets detection",
				"Track access to sensitive resources",
				"Alert on misconfiguration exposures",
			},
			MitigationStrategies: []string{
				"Encrypt data at rest and in transit",
				"Implement secrets management systems",
				"Use data classification and DLP",
				"Regular access reviews and least privilege",
			},
			Keywords: []string{
				"disclosure", "exposure", "leak", "breach", "exfiltration",
				"information disclosure", "sensitive data", "confidentiality",
				"privacy", "secrets", "credentials", "pii", "directory traversal",
			},
			CWEIDs: []int{22, 200, 209, 215, 312, 319, 326, 327, 359, 532, 538},
		},
		DenialOfService: {
			Code:     DenialOfService,
			FullName: "Denial of Service",
			Question: "Can you still operate?",
			Description: "Availability is a security property. Resource exhaustion, " +
				"amplification, logic DoS. The death by a thousand requests.",
			ImpactAreas: []string{"Availability", "Resilience", "Performance", "Operations"},
			DetectionStrategies: []string{
				"Monitor resource utilization trends",
				"Implement rate limiting and quotas",
				"Track request patterns for anomalies",
				"Alert on service degradation",
			},
			MitigationStrategies: []string{
				"Implement rate limiting and backpressure",
				"Use CDN and DDoS protection",
				"Design for graceful degradation",
				"Implement circuit breakers",
			},
			Keywords: []string{
				"dos", "ddos", "denial of service", "resource exhaustion",
				"amplification", "flood", "cpu", "memory", "regex", "algorithmic complexity",
			},
			CWEIDs: []int{400, 404, 770, 776, 834, 835},
		},
		Elevation: {
			Code:     Elevation,
			FullName: "Elevation of Privilege",
			Question: "What can they reach now?",
			Description: "Every privilege is a blast radius. Privesc CVEs, misconfigs, " +
				"confused deputies. The janitor with the master key.",
			ImpactAreas: []string{"Authorization", "Privileges", "Access Control", "Blast Radius"},
			DetectionStrategies: []string{
				"Monitor privilege escalation attempts",
				"Track use of administrative privileges",
				"Alert on unexpected process behavior",
				"Implement least privilege enforcement",
			},
			MitigationStrategies: []string{
				"Enforce principle of least privilege",
				"Use just-in-time access provisioning",
				"Implement privilege access management",
				"Regular privilege audits and reviews",
			},
			Keywords: []string{
				"privilege escalation", "elevation", "privesc", "root", "admin",
				"sudo", "setuid", "capabilities", "authorization", "access control",
			},
			CWEIDs: []int{269, 274, 277, 278, 282, 283, 284, 285, 862, 863},
		},
		LateralMovement: {
			Code:     LateralMovement,
			FullName: "Lateral Movement",
			Question: "Where are they going next?",
			Description: "Breach is a moment; compromise is a journey. Pivoting, " +
				"credential reuse, trust exploitation. The attacker who's already inside.",
			ImpactAreas: []string{"Network Security", "Segmentation", "Trust Boundaries", "Containment"},
			DetectionStrategies: []string{
				"Monitor lateral network movements",
				"Track credential reuse across systems",
				"Alert on unusual access patterns",
				"Implement micro-segmentation",
			},
			MitigationStrategies: []string{
				"Implement network segmentation",
				"Use zero-trust architecture",
				"Enforce explicit trust verification",
				"Monitor and restrict east-west traffic",
			},
			Keywords: []string{
				"lateral movement", "pivoting", "network traversal", "smb", "rdp",
				"pass the hash", "credential reuse", "east-west", "internal network",
			},
			CWEIDs: []int{653},
		},
		Malware: {
			Code:     Malware,
			FullName: "Malware",
			Question: "What did they leave behind?",
			Description: "Code with hostile intent. Implants, C2, persistence mechanisms. " +
				"The gift that keeps on taking.",
			ImpactAreas: []string{"Code Integrity", "Persistence", "Detection", "Response"},
			DetectionStrategies: []string{
				"Deploy endpoint detection and response",
				"Monitor for persistence mechanisms",
				"Track C2 communication patterns",
				"Implement behavioral analysis",
			},
			MitigationStrategies: []string{
				"Deploy EDR/XDR solutions",
				"Implement application whitelisting",
				"Use behavioral analysis and sandboxing",
				"Regular threat hunting exercises",
			},
			Keywords: []string{
				"malware", "trojan", "backdoor", "c2", "command and control",
				"ransomware", "rootkit", "persistence", "implant", "remote access",
				"cryptominer", "botnet", "rat", "apt",
			},
			CWEIDs: []int{506, 912},
		},
	}
}

// GetCategoryInfo returns information about a specific category
func GetCategoryInfo(cat Category) CategoryInfo {
	categories := AllCategories()
	if info, ok := categories[cat]; ok {
		return info
	}
	// Return empty info if not found
	return CategoryInfo{}
}
