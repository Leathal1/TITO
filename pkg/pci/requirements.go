package pci

// Requirement represents a PCI DSS v4.0 requirement
type Requirement struct {
	ID          string
	Title       string
	Description string
	Category    string // One of the 12 main categories
	SubRequirements []SubRequirement
}

// SubRequirement represents a sub-requirement within a PCI DSS requirement
type SubRequirement struct {
	ID          string
	Description string
	Relevant    bool // Whether relevant to application/code security
}

// RequirementCategory represents one of the 12 PCI DSS categories
type RequirementCategory struct {
	Number      int
	Title       string
	Description string
}

// AllCategories returns all 12 PCI DSS v4.0 top-level categories
func AllCategories() []RequirementCategory {
	return []RequirementCategory{
		{
			Number:      1,
			Title:       "Install and Maintain Network Security Controls",
			Description: "Firewalls and routers are key components of the network architecture",
		},
		{
			Number:      2,
			Title:       "Apply Secure Configurations to All System Components",
			Description: "Malicious individuals use default passwords and security settings to compromise systems",
		},
		{
			Number:      3,
			Title:       "Protect Stored Account Data",
			Description: "Protection of cardholder data is critical",
		},
		{
			Number:      4,
			Title:       "Protect Cardholder Data with Strong Cryptography During Transmission",
			Description: "Sensitive data must be encrypted during transmission over public networks",
		},
		{
			Number:      5,
			Title:       "Protect All Systems and Networks from Malicious Software",
			Description: "Malicious software can enter the network during business-approved activities",
		},
		{
			Number:      6,
			Title:       "Develop and Maintain Secure Systems and Software",
			Description: "Security vulnerabilities in systems and software can allow criminals to access cardholder data",
		},
		{
			Number:      7,
			Title:       "Restrict Access to System Components and Cardholder Data by Business Need to Know",
			Description: "Access should be limited to those with a business need",
		},
		{
			Number:      8,
			Title:       "Identify Users and Authenticate Access to System Components",
			Description: "Assigning a unique ID ensures accountability for actions performed",
		},
		{
			Number:      9,
			Title:       "Restrict Physical Access to Cardholder Data",
			Description: "Physical access to data or systems provides the opportunity to access devices or data",
		},
		{
			Number:      10,
			Title:       "Log and Monitor All Access to System Components and Cardholder Data",
			Description: "Logging mechanisms track user activities and detect suspicious activities",
		},
		{
			Number:      11,
			Title:       "Test Security of Systems and Networks Regularly",
			Description: "Vulnerabilities are discovered continuously by hackers and researchers",
		},
		{
			Number:      12,
			Title:       "Support Information Security with Organizational Policies and Programs",
			Description: "The organization's overall information security policy sets the tone for the whole entity",
		},
	}
}

// AllRequirements returns all PCI DSS v4.0 requirements relevant to code/application security
func AllRequirements() []Requirement {
	return []Requirement{
		// Requirement 1: Network Security Controls
		{
			ID:       "1",
			Title:    "Install and Maintain Network Security Controls",
			Description: "Network security controls are critical for protecting the cardholder data environment",
			Category: "Network Security",
			SubRequirements: []SubRequirement{
				{
					ID:          "1.2.7",
					Description: "Configuration files for network security controls are secured from unauthorized access",
					Relevant:    true,
				},
				{
					ID:          "1.4.2",
					Description: "Inbound traffic from untrusted networks to trusted networks is restricted",
					Relevant:    true,
				},
			},
		},
		
		// Requirement 2: Secure Configurations
		{
			ID:       "2",
			Title:    "Apply Secure Configurations to All System Components",
			Description: "Default passwords and security settings are often publicly known and easily guessable",
			Category: "Secure Configuration",
			SubRequirements: []SubRequirement{
				{
					ID:          "2.2.2",
					Description: "Vendor default accounts are managed",
					Relevant:    true,
				},
				{
					ID:          "2.2.4",
					Description: "Only necessary services, protocols, and ports are enabled",
					Relevant:    true,
				},
				{
					ID:          "2.2.7",
					Description: "All non-console administrative access is encrypted using strong cryptography",
					Relevant:    true,
				},
			},
		},
		
		// Requirement 3: Protect Stored Account Data
		{
			ID:       "3",
			Title:    "Protect Stored Account Data",
			Description: "Protection methods such as encryption, truncation, masking, and hashing are critical",
			Category: "Data Protection",
			SubRequirements: []SubRequirement{
				{
					ID:          "3.2.1",
					Description: "Account data storage is kept to a minimum through implementation of data retention and disposal policies",
					Relevant:    true,
				},
				{
					ID:          "3.3.1",
					Description: "Sensitive authentication data (SAD) is not retained after authorization",
					Relevant:    true,
				},
				{
					ID:          "3.3.2",
					Description: "Sensitive authentication data is not stored after authorization, even if encrypted",
					Relevant:    true,
				},
				{
					ID:          "3.3.3",
					Description: "The card verification code (CAV2/CVC2/CVV2/CID) is not stored after authorization",
					Relevant:    true,
				},
				{
					ID:          "3.5.1",
					Description: "Primary account number (PAN) is secured wherever it is stored",
					Relevant:    true,
				},
				{
					ID:          "3.6.1",
					Description: "Procedures for protecting cryptographic keys are defined and implemented",
					Relevant:    true,
				},
				{
					ID:          "3.7.1",
					Description: "Access to cleartext cryptographic key components is restricted to the fewest number of custodians necessary",
					Relevant:    true,
				},
			},
		},
		
		// Requirement 4: Protect Data in Transit
		{
			ID:       "4",
			Title:    "Protect Cardholder Data with Strong Cryptography During Transmission",
			Description: "Sensitive information must be encrypted during transmission over public networks",
			Category: "Encryption in Transit",
			SubRequirements: []SubRequirement{
				{
					ID:          "4.2.1",
					Description: "Strong cryptography and security protocols are implemented to safeguard PAN during transmission",
					Relevant:    true,
				},
				{
					ID:          "4.2.1.1",
					Description: "An inventory of trusted keys and certificates is maintained",
					Relevant:    true,
				},
				{
					ID:          "4.2.1.2",
					Description: "Wireless networks transmitting cardholder data or connected to the CDE use strong cryptography",
					Relevant:    true,
				},
			},
		},
		
		// Requirement 5: Protect from Malware
		{
			ID:       "5",
			Title:    "Protect All Systems and Networks from Malicious Software",
			Description: "Anti-malware solutions protect against malware entering the environment",
			Category: "Malware Protection",
			SubRequirements: []SubRequirement{
				{
					ID:          "5.2.1",
					Description: "Anti-malware mechanisms are configured to perform periodic scans and active/real-time scans",
					Relevant:    false,
				},
				{
					ID:          "5.3.2",
					Description: "Anti-malware mechanisms and definitions are kept current",
					Relevant:    false,
				},
			},
		},
		
		// Requirement 6: Secure Systems and Software
		{
			ID:       "6",
			Title:    "Develop and Maintain Secure Systems and Software",
			Description: "Unscrupulous individuals use security vulnerabilities to gain privileged access to systems",
			Category: "Secure Development",
			SubRequirements: []SubRequirement{
				{
					ID:          "6.2.2",
					Description: "Bespoke and custom software is reviewed prior to being released to production",
					Relevant:    true,
				},
				{
					ID:          "6.2.3",
					Description: "Pre-production environments are separated from production environments",
					Relevant:    true,
				},
				{
					ID:          "6.2.4",
					Description: "Software engineering techniques are applied to prevent or mitigate common software attacks and vulnerabilities",
					Relevant:    true,
				},
				{
					ID:          "6.3.1",
					Description: "Security vulnerabilities are identified and addressed",
					Relevant:    true,
				},
				{
					ID:          "6.3.2",
					Description: "An inventory of bespoke and custom software is maintained",
					Relevant:    true,
				},
				{
					ID:          "6.3.3",
					Description: "All system components are protected from known vulnerabilities by installing applicable security patches",
					Relevant:    true,
				},
				{
					ID:          "6.4.1",
					Description: "Public-facing web applications are protected against attacks",
					Relevant:    true,
				},
				{
					ID:          "6.4.2",
					Description: "Payment page scripts are managed to ensure security of the transaction",
					Relevant:    true,
				},
				{
					ID:          "6.5.1",
					Description: "Change control processes are implemented",
					Relevant:    true,
				},
			},
		},
		
		// Requirement 7: Restrict Access
		{
			ID:       "7",
			Title:    "Restrict Access to System Components and Cardholder Data by Business Need to Know",
			Description: "Critical data or systems become more vulnerable when accessible to unnecessary people",
			Category: "Access Control",
			SubRequirements: []SubRequirement{
				{
					ID:          "7.2.1",
					Description: "An access control model is defined and implemented",
					Relevant:    true,
				},
				{
					ID:          "7.2.2",
					Description: "Access to system components and data is assigned based on individuals' job functions",
					Relevant:    true,
				},
				{
					ID:          "7.2.4",
					Description: "All user access is reviewed periodically",
					Relevant:    true,
				},
				{
					ID:          "7.2.5",
					Description: "All application and system accounts and related access privileges are assigned and managed",
					Relevant:    true,
				},
				{
					ID:          "7.2.6",
					Description: "All user account access to query repositories of stored cardholder data is restricted",
					Relevant:    true,
				},
				{
					ID:          "7.3.1",
					Description: "Access to system components and data is managed via an access control system(s)",
					Relevant:    true,
				},
			},
		},
		
		// Requirement 8: Identify and Authenticate Users
		{
			ID:       "8",
			Title:    "Identify Users and Authenticate Access to System Components",
			Description: "Assigning a unique identification ensures actions performed by each individual can be traced",
			Category: "Authentication",
			SubRequirements: []SubRequirement{
				{
					ID:          "8.2.1",
					Description: "Strong authentication for users and administrators is established and managed",
					Relevant:    true,
				},
				{
					ID:          "8.2.2",
					Description: "Strong authentication for service providers with remote access is managed",
					Relevant:    true,
				},
				{
					ID:          "8.3.1",
					Description: "Multi-factor authentication (MFA) is implemented for all access into the CDE",
					Relevant:    true,
				},
				{
					ID:          "8.3.2",
					Description: "MFA is implemented for all access to the CDE",
					Relevant:    true,
				},
				{
					ID:          "8.3.6",
					Description: "Authentication mechanisms are independent of one another",
					Relevant:    true,
				},
				{
					ID:          "8.3.9",
					Description: "Access to application and system accounts is managed",
					Relevant:    true,
				},
				{
					ID:          "8.4.2",
					Description: "MFA is implemented for all access to system components",
					Relevant:    true,
				},
				{
					ID:          "8.5.1",
					Description: "MFA systems are configured to prevent misuse",
					Relevant:    true,
				},
				{
					ID:          "8.6.1",
					Description: "If passwords are used, complexity and strength requirements are implemented",
					Relevant:    true,
				},
				{
					ID:          "8.6.2",
					Description: "If passwords are used, minimum password length is established",
					Relevant:    true,
				},
				{
					ID:          "8.6.3",
					Description: "If passwords are used, password history is maintained",
					Relevant:    true,
				},
			},
		},
		
		// Requirement 9: Physical Access (less relevant to code)
		{
			ID:       "9",
			Title:    "Restrict Physical Access to Cardholder Data",
			Description: "Physical access to data or systems provides the opportunity to compromise information",
			Category: "Physical Security",
			SubRequirements: []SubRequirement{
				{
					ID:          "9.1.2",
					Description: "Physical access controls are in place to restrict access to cardholder data",
					Relevant:    false,
				},
			},
		},
		
		// Requirement 10: Logging and Monitoring
		{
			ID:       "10",
			Title:    "Log and Monitor All Access to System Components and Cardholder Data",
			Description: "Logging mechanisms track user activities and reconstruct events after compromise",
			Category: "Logging",
			SubRequirements: []SubRequirement{
				{
					ID:          "10.2.1",
					Description: "Audit logs capture all individual user access to cardholder data",
					Relevant:    true,
				},
				{
					ID:          "10.2.1.1",
					Description: "Audit log entries are generated for all access to cardholder data",
					Relevant:    true,
				},
				{
					ID:          "10.2.1.2",
					Description: "Audit log entries are generated for all actions by individuals with administrative access",
					Relevant:    true,
				},
				{
					ID:          "10.2.1.3",
					Description: "Audit log entries are generated for all access to audit logs",
					Relevant:    true,
				},
				{
					ID:          "10.2.1.4",
					Description: "Audit log entries are generated for all invalid logical access attempts",
					Relevant:    true,
				},
				{
					ID:          "10.2.1.5",
					Description: "Audit log entries are generated for all changes to identification and authentication credentials",
					Relevant:    true,
				},
				{
					ID:          "10.2.1.6",
					Description: "Audit log entries are generated for all initialization of audit logs",
					Relevant:    true,
				},
				{
					ID:          "10.2.2",
					Description: "Audit logs are implemented to support anomaly detection",
					Relevant:    true,
				},
				{
					ID:          "10.3.1",
					Description: "Audit log entries contain sufficient detail to reconstruct events",
					Relevant:    true,
				},
				{
					ID:          "10.3.2",
					Description: "User identity is captured in audit logs",
					Relevant:    true,
				},
				{
					ID:          "10.4.1",
					Description: "A log review is performed for all system components",
					Relevant:    true,
				},
				{
					ID:          "10.4.2",
					Description: "Logs for critical security control systems are reviewed frequently",
					Relevant:    true,
				},
			},
		},
		
		// Requirement 11: Security Testing
		{
			ID:       "11",
			Title:    "Test Security of Systems and Networks Regularly",
			Description: "Vulnerabilities are continuously discovered by hackers and researchers",
			Category: "Security Testing",
			SubRequirements: []SubRequirement{
				{
					ID:          "11.3.1",
					Description: "External vulnerability scans are performed",
					Relevant:    true,
				},
				{
					ID:          "11.3.2",
					Description: "Internal vulnerability scans are performed",
					Relevant:    true,
				},
				{
					ID:          "11.4.1",
					Description: "Penetration testing is performed",
					Relevant:    true,
				},
				{
					ID:          "11.5.1",
					Description: "Network intrusions and unexpected file changes are detected",
					Relevant:    true,
				},
				{
					ID:          "11.6.1",
					Description: "Unauthorized changes on payment pages are detected and responded to",
					Relevant:    true,
				},
			},
		},
		
		// Requirement 12: Information Security Policy
		{
			ID:       "12",
			Title:    "Support Information Security with Organizational Policies and Programs",
			Description: "The organization's information security policy sets the tone for security culture",
			Category: "Policy",
			SubRequirements: []SubRequirement{
				{
					ID:          "12.3.1",
					Description: "Personnel are trained in security awareness",
					Relevant:    false,
				},
				{
					ID:          "12.6.1",
					Description: "Security awareness training is provided to all personnel",
					Relevant:    false,
				},
				{
					ID:          "12.6.3",
					Description: "Personnel acknowledge they have read and understood the information security policy",
					Relevant:    false,
				},
			},
		},
	}
}

// GetRequirementByID returns a requirement by its ID
func GetRequirementByID(id string) *Requirement {
	requirements := AllRequirements()
	for _, req := range requirements {
		if req.ID == id {
			return &req
		}
	}
	return nil
}

// GetAllRelevantSubRequirements returns all sub-requirements marked as relevant to code/app security
func GetAllRelevantSubRequirements() []SubRequirement {
	var relevant []SubRequirement
	requirements := AllRequirements()
	for _, req := range requirements {
		for _, subReq := range req.SubRequirements {
			if subReq.Relevant {
				relevant = append(relevant, subReq)
			}
		}
	}
	return relevant
}

// RequirementStatus represents the compliance status of a requirement
type RequirementStatus string

const (
	StatusPass    RequirementStatus = "Pass"
	StatusFail    RequirementStatus = "Fail"
	StatusPartial RequirementStatus = "Partial"
	StatusNotTested RequirementStatus = "Not Tested"
)
