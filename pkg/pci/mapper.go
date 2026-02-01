package pci

import (
	"fmt"
	"strings"

	"github.com/Leathal1/TITO/pkg/stridelm"
)

// Mapping represents a mapping between a threat and PCI DSS requirements
type Mapping struct {
	RequirementID string
	SubRequirementID string
	Confidence    float64 // 0.0 to 1.0
	Reason        string
}

// Mapper maps threats to PCI DSS v4.0 requirements
type Mapper struct {
	requirements []Requirement
}

// NewMapper creates a new PCI DSS mapper
func NewMapper() *Mapper {
	return &Mapper{
		requirements: AllRequirements(),
	}
}

// MapThreat maps a threat to PCI DSS requirements based on multiple signals
func (m *Mapper) MapThreat(title, description string, strideCategory stridelm.Category, cweIDs []string, semgrepRuleIDs []string) []Mapping {
	mappings := make([]Mapping, 0)
	titleLower := strings.ToLower(title)
	descLower := strings.ToLower(description)
	combined := titleLower + " " + descLower

	// Map based on STRIDE-LM category
	strideMappings := m.mapBySTRIDE(strideCategory)
	mappings = append(mappings, strideMappings...)

	// Map based on CWE IDs
	cweMappings := m.mapByCWE(cweIDs)
	mappings = append(mappings, cweMappings...)

	// Map based on keywords in title/description
	keywordMappings := m.mapByKeywords(combined)
	mappings = append(mappings, keywordMappings...)

	// Map based on Semgrep rule IDs
	semgrepMappings := m.mapBySemgrepRules(semgrepRuleIDs)
	mappings = append(mappings, semgrepMappings...)

	// Deduplicate and merge confidence scores
	return m.deduplicate(mappings)
}

// mapBySTRIDE maps STRIDE-LM categories to PCI requirements
func (m *Mapper) mapBySTRIDE(category stridelm.Category) []Mapping {
	mappings := make([]Mapping, 0)

	switch category {
	case stridelm.Spoofing:
		mappings = append(mappings, Mapping{
			RequirementID: "8",
			SubRequirementID: "8.2.1",
			Confidence: 0.85,
			Reason: "Spoofing threats relate to authentication weaknesses (Req 8.2.1)",
		})
		mappings = append(mappings, Mapping{
			RequirementID: "8",
			SubRequirementID: "8.3.1",
			Confidence: 0.75,
			Reason: "Spoofing can be mitigated with multi-factor authentication (Req 8.3.1)",
		})

	case stridelm.Tampering:
		mappings = append(mappings, Mapping{
			RequirementID: "6",
			SubRequirementID: "6.2.4",
			Confidence: 0.8,
			Reason: "Tampering threats indicate input validation vulnerabilities (Req 6.2.4)",
		})
		mappings = append(mappings, Mapping{
			RequirementID: "10",
			SubRequirementID: "10.2.2",
			Confidence: 0.7,
			Reason: "Tampering detection requires audit logging (Req 10.2.2)",
		})

	case stridelm.Repudiation:
		mappings = append(mappings, Mapping{
			RequirementID: "10",
			SubRequirementID: "10.2.1",
			Confidence: 0.9,
			Reason: "Repudiation threats require comprehensive audit logs (Req 10.2.1)",
		})
		mappings = append(mappings, Mapping{
			RequirementID: "10",
			SubRequirementID: "10.3.1",
			Confidence: 0.85,
			Reason: "Audit logs must contain sufficient detail to reconstruct events (Req 10.3.1)",
		})

	case stridelm.InfoDisclosure:
		mappings = append(mappings, Mapping{
			RequirementID: "3",
			SubRequirementID: "3.5.1",
			Confidence: 0.9,
			Reason: "Information disclosure threatens stored cardholder data (Req 3.5.1)",
		})
		mappings = append(mappings, Mapping{
			RequirementID: "4",
			SubRequirementID: "4.2.1",
			Confidence: 0.85,
			Reason: "Data in transit must be encrypted (Req 4.2.1)",
		})
		mappings = append(mappings, Mapping{
			RequirementID: "7",
			SubRequirementID: "7.2.1",
			Confidence: 0.75,
			Reason: "Access controls prevent unauthorized data disclosure (Req 7.2.1)",
		})

	case stridelm.DenialOfService:
		mappings = append(mappings, Mapping{
			RequirementID: "6",
			SubRequirementID: "6.2.4",
			Confidence: 0.7,
			Reason: "DoS vulnerabilities should be prevented through secure coding (Req 6.2.4)",
		})
		mappings = append(mappings, Mapping{
			RequirementID: "11",
			SubRequirementID: "11.3.1",
			Confidence: 0.65,
			Reason: "Vulnerability scanning can detect DoS weaknesses (Req 11.3.1)",
		})

	case stridelm.Elevation:
		mappings = append(mappings, Mapping{
			RequirementID: "7",
			SubRequirementID: "7.2.2",
			Confidence: 0.9,
			Reason: "Privilege escalation violates least privilege principle (Req 7.2.2)",
		})
		mappings = append(mappings, Mapping{
			RequirementID: "8",
			SubRequirementID: "8.2.1",
			Confidence: 0.8,
			Reason: "Strong authentication prevents privilege escalation (Req 8.2.1)",
		})

	case stridelm.LateralMovement:
		mappings = append(mappings, Mapping{
			RequirementID: "7",
			SubRequirementID: "7.2.1",
			Confidence: 0.85,
			Reason: "Lateral movement indicates access control failures (Req 7.2.1)",
		})
		mappings = append(mappings, Mapping{
			RequirementID: "1",
			SubRequirementID: "1.4.2",
			Confidence: 0.75,
			Reason: "Network segmentation prevents lateral movement (Req 1.4.2)",
		})

	case stridelm.Malware:
		mappings = append(mappings, Mapping{
			RequirementID: "6",
			SubRequirementID: "6.2.4",
			Confidence: 0.8,
			Reason: "Secure coding prevents malware injection (Req 6.2.4)",
		})
		mappings = append(mappings, Mapping{
			RequirementID: "6",
			SubRequirementID: "6.4.1",
			Confidence: 0.75,
			Reason: "Web application protection prevents malware delivery (Req 6.4.1)",
		})
	}

	return mappings
}

// mapByCWE maps CWE IDs to PCI requirements
func (m *Mapper) mapByCWE(cweIDs []string) []Mapping {
	mappings := make([]Mapping, 0)

	for _, cweID := range cweIDs {
		cweLower := strings.ToLower(cweID)
		
		// Injection vulnerabilities
		if strings.Contains(cweLower, "89") || // SQL Injection
		   strings.Contains(cweLower, "79") || // XSS
		   strings.Contains(cweLower, "78") || // OS Command Injection
		   strings.Contains(cweLower, "90") { // LDAP Injection
			mappings = append(mappings, Mapping{
				RequirementID: "6",
				SubRequirementID: "6.2.4",
				Confidence: 0.95,
				Reason: fmt.Sprintf("CWE %s: Injection vulnerabilities must be prevented (Req 6.2.4)", cweID),
			})
			mappings = append(mappings, Mapping{
				RequirementID: "6",
				SubRequirementID: "6.4.1",
				Confidence: 0.85,
				Reason: fmt.Sprintf("CWE %s: Web applications must be protected (Req 6.4.1)", cweID),
			})
		}

		// Authentication/credential issues
		if strings.Contains(cweLower, "798") || // Hardcoded Credentials
		   strings.Contains(cweLower, "259") || // Hard-coded Password
		   strings.Contains(cweLower, "321") || // Use of Hard-coded Cryptographic Key
		   strings.Contains(cweLower, "798") { // Use of Hard-coded Credentials
			mappings = append(mappings, Mapping{
				RequirementID: "8",
				SubRequirementID: "8.2.1",
				Confidence: 0.95,
				Reason: fmt.Sprintf("CWE %s: Strong authentication required (Req 8.2.1)", cweID),
			})
			mappings = append(mappings, Mapping{
				RequirementID: "3",
				SubRequirementID: "3.6.1",
				Confidence: 0.85,
				Reason: fmt.Sprintf("CWE %s: Cryptographic keys must be protected (Req 3.6.1)", cweID),
			})
		}

		// Weak cryptography
		if strings.Contains(cweLower, "327") || // Broken or Risky Crypto
		   strings.Contains(cweLower, "326") || // Inadequate Encryption Strength
		   strings.Contains(cweLower, "328") { // Reversible One-Way Hash
			mappings = append(mappings, Mapping{
				RequirementID: "4",
				SubRequirementID: "4.2.1",
				Confidence: 0.9,
				Reason: fmt.Sprintf("CWE %s: Strong cryptography required for data in transit (Req 4.2.1)", cweID),
			})
			mappings = append(mappings, Mapping{
				RequirementID: "3",
				SubRequirementID: "3.5.1",
				Confidence: 0.9,
				Reason: fmt.Sprintf("CWE %s: Strong cryptography required for stored data (Req 3.5.1)", cweID),
			})
		}

		// Access control issues
		if strings.Contains(cweLower, "284") || // Improper Access Control
		   strings.Contains(cweLower, "285") || // Improper Authorization
		   strings.Contains(cweLower, "862") { // Missing Authorization
			mappings = append(mappings, Mapping{
				RequirementID: "7",
				SubRequirementID: "7.2.1",
				Confidence: 0.9,
				Reason: fmt.Sprintf("CWE %s: Access control model required (Req 7.2.1)", cweID),
			})
			mappings = append(mappings, Mapping{
				RequirementID: "7",
				SubRequirementID: "7.3.1",
				Confidence: 0.85,
				Reason: fmt.Sprintf("CWE %s: Access control systems required (Req 7.3.1)", cweID),
			})
		}

		// Sensitive data exposure
		if strings.Contains(cweLower, "200") || // Exposure of Sensitive Information
		   strings.Contains(cweLower, "209") || // Generation of Error Message Containing Sensitive Information
		   strings.Contains(cweLower, "532") { // Insertion of Sensitive Information into Log File
			mappings = append(mappings, Mapping{
				RequirementID: "3",
				SubRequirementID: "3.3.1",
				Confidence: 0.9,
				Reason: fmt.Sprintf("CWE %s: Sensitive authentication data must not be retained (Req 3.3.1)", cweID),
			})
			mappings = append(mappings, Mapping{
				RequirementID: "10",
				SubRequirementID: "10.3.1",
				Confidence: 0.8,
				Reason: fmt.Sprintf("CWE %s: Audit logs must not contain sensitive data (Req 10.3.1)", cweID),
			})
		}

		// Logging issues
		if strings.Contains(cweLower, "778") || // Insufficient Logging
		   strings.Contains(cweLower, "223") { // Omission of Security-relevant Information
			mappings = append(mappings, Mapping{
				RequirementID: "10",
				SubRequirementID: "10.2.1",
				Confidence: 0.9,
				Reason: fmt.Sprintf("CWE %s: Comprehensive audit logging required (Req 10.2.1)", cweID),
			})
		}
	}

	return mappings
}

// mapByKeywords maps threat keywords to PCI requirements
func (m *Mapper) mapByKeywords(text string) []Mapping {
	mappings := make([]Mapping, 0)
	text = strings.ToLower(text)

	// SQL Injection
	if strings.Contains(text, "sql injection") || strings.Contains(text, "sqli") {
		mappings = append(mappings, Mapping{
			RequirementID: "6",
			SubRequirementID: "6.2.4",
			Confidence: 0.95,
			Reason: "SQL injection must be prevented through secure coding (Req 6.2.4)",
		})
		mappings = append(mappings, Mapping{
			RequirementID: "6",
			SubRequirementID: "6.4.1",
			Confidence: 0.85,
			Reason: "Web applications must be protected against SQL injection (Req 6.4.1)",
		})
	}

	// XSS
	if strings.Contains(text, "cross-site scripting") || strings.Contains(text, "xss") {
		mappings = append(mappings, Mapping{
			RequirementID: "6",
			SubRequirementID: "6.2.4",
			Confidence: 0.95,
			Reason: "XSS must be prevented through input validation and output encoding (Req 6.2.4)",
		})
		mappings = append(mappings, Mapping{
			RequirementID: "6",
			SubRequirementID: "6.4.1",
			Confidence: 0.9,
			Reason: "Web applications must be protected against XSS (Req 6.4.1)",
		})
	}

	// Hardcoded credentials/secrets
	if strings.Contains(text, "hardcoded") || 
	   strings.Contains(text, "hard-coded") ||
	   strings.Contains(text, "embedded credential") ||
	   strings.Contains(text, "default password") {
		mappings = append(mappings, Mapping{
			RequirementID: "8",
			SubRequirementID: "8.2.1",
			Confidence: 0.95,
			Reason: "Hardcoded credentials violate strong authentication requirements (Req 8.2.1)",
		})
		mappings = append(mappings, Mapping{
			RequirementID: "2",
			SubRequirementID: "2.2.2",
			Confidence: 0.9,
			Reason: "Default credentials must be changed (Req 2.2.2)",
		})
		mappings = append(mappings, Mapping{
			RequirementID: "3",
			SubRequirementID: "3.6.1",
			Confidence: 0.85,
			Reason: "Cryptographic keys must not be hardcoded (Req 3.6.1)",
		})
	}

	// Weak cryptography
	if strings.Contains(text, "weak crypto") ||
	   strings.Contains(text, "weak encryption") ||
	   strings.Contains(text, "insecure algorithm") ||
	   strings.Contains(text, "md5") ||
	   strings.Contains(text, "sha1") ||
	   strings.Contains(text, "des") {
		mappings = append(mappings, Mapping{
			RequirementID: "4",
			SubRequirementID: "4.2.1",
			Confidence: 0.95,
			Reason: "Strong cryptography required for data in transit (Req 4.2.1)",
		})
		mappings = append(mappings, Mapping{
			RequirementID: "3",
			SubRequirementID: "3.5.1",
			Confidence: 0.9,
			Reason: "Strong cryptography required for stored cardholder data (Req 3.5.1)",
		})
	}

	// Missing authentication
	if strings.Contains(text, "missing authentication") ||
	   strings.Contains(text, "no authentication") ||
	   strings.Contains(text, "unauthenticated") {
		mappings = append(mappings, Mapping{
			RequirementID: "8",
			SubRequirementID: "8.2.1",
			Confidence: 0.95,
			Reason: "All access must be authenticated (Req 8.2.1)",
		})
		mappings = append(mappings, Mapping{
			RequirementID: "7",
			SubRequirementID: "7.2.1",
			Confidence: 0.85,
			Reason: "Access control model required (Req 7.2.1)",
		})
	}

	// Missing authorization
	if strings.Contains(text, "missing authorization") ||
	   strings.Contains(text, "no authorization") ||
	   strings.Contains(text, "unauthorized access") {
		mappings = append(mappings, Mapping{
			RequirementID: "7",
			SubRequirementID: "7.2.1",
			Confidence: 0.95,
			Reason: "Authorization controls required (Req 7.2.1)",
		})
		mappings = append(mappings, Mapping{
			RequirementID: "7",
			SubRequirementID: "7.3.1",
			Confidence: 0.9,
			Reason: "Access control systems required (Req 7.3.1)",
		})
	}

	// Logging gaps
	if strings.Contains(text, "insufficient logging") ||
	   strings.Contains(text, "missing log") ||
	   strings.Contains(text, "no audit") {
		mappings = append(mappings, Mapping{
			RequirementID: "10",
			SubRequirementID: "10.2.1",
			Confidence: 0.9,
			Reason: "Comprehensive audit logging required (Req 10.2.1)",
		})
		mappings = append(mappings, Mapping{
			RequirementID: "10",
			SubRequirementID: "10.3.1",
			Confidence: 0.85,
			Reason: "Audit logs must contain sufficient detail (Req 10.3.1)",
		})
	}

	// Sensitive data in logs
	if strings.Contains(text, "sensitive data in log") ||
	   strings.Contains(text, "card number in log") ||
	   strings.Contains(text, "password in log") {
		mappings = append(mappings, Mapping{
			RequirementID: "3",
			SubRequirementID: "3.3.1",
			Confidence: 0.95,
			Reason: "Sensitive authentication data must not be logged (Req 3.3.1)",
		})
		mappings = append(mappings, Mapping{
			RequirementID: "10",
			SubRequirementID: "10.3.1",
			Confidence: 0.9,
			Reason: "Audit logs must not contain sensitive authentication data (Req 10.3.1)",
		})
	}

	// TLS/SSL issues
	if strings.Contains(text, "missing tls") ||
	   strings.Contains(text, "no encryption") ||
	   strings.Contains(text, "unencrypted") ||
	   strings.Contains(text, "plaintext") {
		mappings = append(mappings, Mapping{
			RequirementID: "4",
			SubRequirementID: "4.2.1",
			Confidence: 0.95,
			Reason: "Strong cryptography required for transmission (Req 4.2.1)",
		})
		mappings = append(mappings, Mapping{
			RequirementID: "2",
			SubRequirementID: "2.2.7",
			Confidence: 0.85,
			Reason: "Non-console administrative access must be encrypted (Req 2.2.7)",
		})
	}

	// Password policy issues
	if strings.Contains(text, "weak password") ||
	   strings.Contains(text, "password complexity") ||
	   strings.Contains(text, "password policy") {
		mappings = append(mappings, Mapping{
			RequirementID: "8",
			SubRequirementID: "8.6.1",
			Confidence: 0.9,
			Reason: "Password complexity requirements must be implemented (Req 8.6.1)",
		})
		mappings = append(mappings, Mapping{
			RequirementID: "8",
			SubRequirementID: "8.6.2",
			Confidence: 0.85,
			Reason: "Minimum password length must be established (Req 8.6.2)",
		})
	}

	// MFA issues
	if strings.Contains(text, "missing mfa") ||
	   strings.Contains(text, "no multi-factor") ||
	   strings.Contains(text, "no 2fa") {
		mappings = append(mappings, Mapping{
			RequirementID: "8",
			SubRequirementID: "8.3.1",
			Confidence: 0.95,
			Reason: "Multi-factor authentication required for CDE access (Req 8.3.1)",
		})
		mappings = append(mappings, Mapping{
			RequirementID: "8",
			SubRequirementID: "8.4.2",
			Confidence: 0.9,
			Reason: "MFA required for all system component access (Req 8.4.2)",
		})
	}

	// Cardholder data exposure
	if strings.Contains(text, "pan") ||
	   strings.Contains(text, "card number") ||
	   strings.Contains(text, "cardholder data") ||
	   strings.Contains(text, "credit card") {
		mappings = append(mappings, Mapping{
			RequirementID: "3",
			SubRequirementID: "3.5.1",
			Confidence: 0.95,
			Reason: "Primary account number must be secured (Req 3.5.1)",
		})
		mappings = append(mappings, Mapping{
			RequirementID: "3",
			SubRequirementID: "3.2.1",
			Confidence: 0.85,
			Reason: "Account data storage must be minimized (Req 3.2.1)",
		})
	}

	return mappings
}

// mapBySemgrepRules maps Semgrep rule IDs to PCI requirements
func (m *Mapper) mapBySemgrepRules(ruleIDs []string) []Mapping {
	mappings := make([]Mapping, 0)

	for _, ruleID := range ruleIDs {
		ruleLower := strings.ToLower(ruleID)

		// PCI-specific rules (if they exist)
		if strings.Contains(ruleLower, "pci") {
			// Extract requirement from rule ID if formatted as pci-req-X-Y
			if strings.Contains(ruleLower, "pci-cardholder") {
				mappings = append(mappings, Mapping{
					RequirementID: "3",
					SubRequirementID: "3.5.1",
					Confidence: 0.95,
					Reason: fmt.Sprintf("PCI-specific rule: %s", ruleID),
				})
			}
			if strings.Contains(ruleLower, "pci-crypto") {
				mappings = append(mappings, Mapping{
					RequirementID: "4",
					SubRequirementID: "4.2.1",
					Confidence: 0.95,
					Reason: fmt.Sprintf("PCI-specific rule: %s", ruleID),
				})
			}
			if strings.Contains(ruleLower, "pci-auth") {
				mappings = append(mappings, Mapping{
					RequirementID: "8",
					SubRequirementID: "8.2.1",
					Confidence: 0.95,
					Reason: fmt.Sprintf("PCI-specific rule: %s", ruleID),
				})
			}
			if strings.Contains(ruleLower, "pci-logging") {
				mappings = append(mappings, Mapping{
					RequirementID: "10",
					SubRequirementID: "10.2.1",
					Confidence: 0.95,
					Reason: fmt.Sprintf("PCI-specific rule: %s", ruleID),
				})
			}
		}

		// Generic security rules
		if strings.Contains(ruleLower, "sql-injection") || strings.Contains(ruleLower, "sqli") {
			mappings = append(mappings, Mapping{
				RequirementID: "6",
				SubRequirementID: "6.2.4",
				Confidence: 0.9,
				Reason: fmt.Sprintf("SQL injection detected by rule: %s", ruleID),
			})
		}

		if strings.Contains(ruleLower, "hardcoded") || strings.Contains(ruleLower, "hard-coded") {
			mappings = append(mappings, Mapping{
				RequirementID: "8",
				SubRequirementID: "8.2.1",
				Confidence: 0.9,
				Reason: fmt.Sprintf("Hardcoded credential detected by rule: %s", ruleID),
			})
		}
	}

	return mappings
}

// deduplicate merges duplicate mappings and combines confidence scores
func (m *Mapper) deduplicate(mappings []Mapping) []Mapping {
	uniqueMap := make(map[string]Mapping)

	for _, mapping := range mappings {
		key := mapping.RequirementID + ":" + mapping.SubRequirementID
		
		if existing, ok := uniqueMap[key]; ok {
			// Keep the higher confidence score and combine reasons
			if mapping.Confidence > existing.Confidence {
				existing.Confidence = mapping.Confidence
			}
			// Combine reasons if different
			if !strings.Contains(existing.Reason, mapping.Reason) {
				existing.Reason = existing.Reason + " | " + mapping.Reason
			}
			uniqueMap[key] = existing
		} else {
			uniqueMap[key] = mapping
		}
	}

	// Convert map back to slice
	result := make([]Mapping, 0, len(uniqueMap))
	for _, mapping := range uniqueMap {
		result = append(result, mapping)
	}

	return result
}

// GetRequirementDetails returns full requirement details for a mapping
func (m *Mapper) GetRequirementDetails(mapping Mapping) (*Requirement, *SubRequirement) {
	req := GetRequirementByID(mapping.RequirementID)
	if req == nil {
		return nil, nil
	}

	for _, subReq := range req.SubRequirements {
		if subReq.ID == mapping.SubRequirementID {
			return req, &subReq
		}
	}

	return req, nil
}
