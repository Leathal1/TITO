package mitre

// Tactic represents a MITRE ATT&CK tactic
type Tactic string

const (
	InitialAccess      Tactic = "TA0001"
	Execution          Tactic = "TA0002"
	Persistence        Tactic = "TA0003"
	PrivilegeEscalation Tactic = "TA0004"
	DefenseEvasion     Tactic = "TA0005"
	CredentialAccess   Tactic = "TA0006"
	Discovery          Tactic = "TA0007"
	LateralMovement    Tactic = "TA0008"
	Collection         Tactic = "TA0009"
	Exfiltration       Tactic = "TA0010"
	CommandAndControl  Tactic = "TA0011"
	Impact             Tactic = "TA0040"
)

// Technique represents a MITRE ATT&CK technique
type Technique struct {
	ID          string
	Name        string
	Description string
	Tactic      Tactic
	Platforms   []string
	Detection   []string
	Mitigation  []string
}

// TacticInfo holds information about a tactic
type TacticInfo struct {
	ID          Tactic
	Name        string
	Description string
}

// AllTactics returns all MITRE ATT&CK tactics
func AllTactics() map[Tactic]TacticInfo {
	return map[Tactic]TacticInfo{
		InitialAccess: {
			ID:          InitialAccess,
			Name:        "Initial Access",
			Description: "The adversary is trying to get into your network.",
		},
		Execution: {
			ID:          Execution,
			Name:        "Execution",
			Description: "The adversary is trying to run malicious code.",
		},
		Persistence: {
			ID:          Persistence,
			Name:        "Persistence",
			Description: "The adversary is trying to maintain their foothold.",
		},
		PrivilegeEscalation: {
			ID:          PrivilegeEscalation,
			Name:        "Privilege Escalation",
			Description: "The adversary is trying to gain higher-level permissions.",
		},
		DefenseEvasion: {
			ID:          DefenseEvasion,
			Name:        "Defense Evasion",
			Description: "The adversary is trying to avoid being detected.",
		},
		CredentialAccess: {
			ID:          CredentialAccess,
			Name:        "Credential Access",
			Description: "The adversary is trying to steal account names and passwords.",
		},
		Discovery: {
			ID:          Discovery,
			Name:        "Discovery",
			Description: "The adversary is trying to figure out your environment.",
		},
		LateralMovement: {
			ID:          LateralMovement,
			Name:        "Lateral Movement",
			Description: "The adversary is trying to move through your environment.",
		},
		Collection: {
			ID:          Collection,
			Name:        "Collection",
			Description: "The adversary is trying to gather data of interest.",
		},
		Exfiltration: {
			ID:          Exfiltration,
			Name:        "Exfiltration",
			Description: "The adversary is trying to steal data.",
		},
		CommandAndControl: {
			ID:          CommandAndControl,
			Name:        "Command and Control",
			Description: "The adversary is trying to communicate with compromised systems.",
		},
		Impact: {
			ID:          Impact,
			Name:        "Impact",
			Description: "The adversary is trying to manipulate, interrupt, or destroy your systems and data.",
		},
	}
}

// AllTechniques returns a subset of common MITRE ATT&CK techniques
func AllTechniques() []Technique {
	return []Technique{
		// Initial Access
		{
			ID:          "T1190",
			Name:        "Exploit Public-Facing Application",
			Description: "Adversaries may exploit software vulnerabilities in Internet-facing applications.",
			Tactic:      InitialAccess,
			Platforms:   []string{"Linux", "Windows", "macOS", "Cloud"},
			Detection:   []string{"Monitor application logs", "Network traffic analysis", "Vulnerability scanning"},
			Mitigation:  []string{"Patch management", "Application isolation", "Security hardening"},
		},
		{
			ID:          "T1133",
			Name:        "External Remote Services",
			Description: "Adversaries may leverage external-facing remote services to gain access.",
			Tactic:      InitialAccess,
			Platforms:   []string{"Linux", "Windows", "macOS"},
			Detection:   []string{"Monitor remote access logs", "Anomalous authentication"},
			Mitigation:  []string{"MFA", "Disable unused services", "Network segmentation"},
		},
		{
			ID:          "T1566",
			Name:        "Phishing",
			Description: "Adversaries may send phishing messages to gain access to victim systems.",
			Tactic:      InitialAccess,
			Platforms:   []string{"Linux", "Windows", "macOS", "Cloud"},
			Detection:   []string{"Email analysis", "User training", "Email gateway filtering"},
			Mitigation:  []string{"Security awareness training", "Email filtering", "Anti-phishing"},
		},

		// Execution
		{
			ID:          "T1059",
			Name:        "Command and Scripting Interpreter",
			Description: "Adversaries may abuse command and script interpreters to execute commands.",
			Tactic:      Execution,
			Platforms:   []string{"Linux", "Windows", "macOS"},
			Detection:   []string{"Process monitoring", "Command-line logging"},
			Mitigation:  []string{"Code signing", "Application whitelisting", "Execution prevention"},
		},
		{
			ID:          "T1203",
			Name:        "Exploitation for Client Execution",
			Description: "Adversaries may exploit software vulnerabilities in client applications.",
			Tactic:      Execution,
			Platforms:   []string{"Linux", "Windows", "macOS"},
			Detection:   []string{"Application behavior monitoring", "Exploit detection"},
			Mitigation:  []string{"Patch management", "Browser hardening", "Disable unnecessary features"},
		},
		{
			ID:          "T1204",
			Name:        "User Execution",
			Description: "Adversaries may rely on user interaction to execute malicious code.",
			Tactic:      Execution,
			Platforms:   []string{"Linux", "Windows", "macOS"},
			Detection:   []string{"Process monitoring", "User behavior analytics"},
			Mitigation:  []string{"User training", "Application control", "Sandboxing"},
		},

		// Persistence
		{
			ID:          "T1543",
			Name:        "Create or Modify System Process",
			Description: "Adversaries may create or modify system processes to maintain persistence.",
			Tactic:      Persistence,
			Platforms:   []string{"Linux", "Windows", "macOS"},
			Detection:   []string{"Service monitoring", "Registry monitoring", "File monitoring"},
			Mitigation:  []string{"Restrict service creation", "User account control"},
		},
		{
			ID:          "T1547",
			Name:        "Boot or Logon Autostart Execution",
			Description: "Adversaries may configure system settings to automatically execute.",
			Tactic:      Persistence,
			Platforms:   []string{"Linux", "Windows", "macOS"},
			Detection:   []string{"Startup folder monitoring", "Registry key monitoring"},
			Mitigation:  []string{"Disable autorun", "User education"},
		},
		{
			ID:          "T1098",
			Name:        "Account Manipulation",
			Description: "Adversaries may manipulate accounts to maintain access.",
			Tactic:      Persistence,
			Platforms:   []string{"Linux", "Windows", "macOS", "Cloud"},
			Detection:   []string{"Account monitoring", "Permission changes"},
			Mitigation:  []string{"MFA", "Privileged account management", "Access reviews"},
		},

		// Privilege Escalation
		{
			ID:          "T1068",
			Name:        "Exploitation for Privilege Escalation",
			Description: "Adversaries may exploit software vulnerabilities to escalate privileges.",
			Tactic:      PrivilegeEscalation,
			Platforms:   []string{"Linux", "Windows", "macOS"},
			Detection:   []string{"System integrity monitoring", "Exploit detection"},
			Mitigation:  []string{"Patch management", "Least privilege", "Exploit protection"},
		},
		{
			ID:          "T1078",
			Name:        "Valid Accounts",
			Description: "Adversaries may use valid credentials to gain access.",
			Tactic:      PrivilegeEscalation,
			Platforms:   []string{"Linux", "Windows", "macOS", "Cloud"},
			Detection:   []string{"Authentication logs", "Anomalous access patterns"},
			Mitigation:  []string{"MFA", "Password policies", "Account segmentation"},
		},

		// Defense Evasion
		{
			ID:          "T1027",
			Name:        "Obfuscated Files or Information",
			Description: "Adversaries may obfuscate files or information to evade detection.",
			Tactic:      DefenseEvasion,
			Platforms:   []string{"Linux", "Windows", "macOS"},
			Detection:   []string{"File analysis", "Behavioral analysis"},
			Mitigation:  []string{"Code signing", "Anti-malware", "Execution prevention"},
		},
		{
			ID:          "T1070",
			Name:        "Indicator Removal",
			Description: "Adversaries may delete or modify artifacts to remove evidence.",
			Tactic:      DefenseEvasion,
			Platforms:   []string{"Linux", "Windows", "macOS"},
			Detection:   []string{"File monitoring", "Process monitoring", "Log analysis"},
			Mitigation:  []string{"Restrict file permissions", "Centralized logging"},
		},
		{
			ID:          "T1562",
			Name:        "Impair Defenses",
			Description: "Adversaries may maliciously modify or disable security defenses.",
			Tactic:      DefenseEvasion,
			Platforms:   []string{"Linux", "Windows", "macOS", "Cloud"},
			Detection:   []string{"Security software monitoring", "Service monitoring"},
			Mitigation:  []string{"Restrict registry permissions", "User account control"},
		},

		// Credential Access
		{
			ID:          "T1110",
			Name:        "Brute Force",
			Description: "Adversaries may use brute force techniques to gain access.",
			Tactic:      CredentialAccess,
			Platforms:   []string{"Linux", "Windows", "macOS", "Cloud"},
			Detection:   []string{"Failed login monitoring", "Rate limiting"},
			Mitigation:  []string{"Account lockout", "MFA", "Password policies"},
		},
		{
			ID:          "T1555",
			Name:        "Credentials from Password Stores",
			Description: "Adversaries may search for credentials in password stores.",
			Tactic:      CredentialAccess,
			Platforms:   []string{"Linux", "Windows", "macOS"},
			Detection:   []string{"File access monitoring", "Process monitoring"},
			Mitigation:  []string{"Password manager security", "Credential encryption"},
		},
		{
			ID:          "T1056",
			Name:        "Input Capture",
			Description: "Adversaries may capture user input to obtain credentials.",
			Tactic:      CredentialAccess,
			Platforms:   []string{"Linux", "Windows", "macOS"},
			Detection:   []string{"Kernel monitoring", "API monitoring"},
			Mitigation:  []string{"Virtual keyboard", "Input validation"},
		},

		// Discovery
		{
			ID:          "T1083",
			Name:        "File and Directory Discovery",
			Description: "Adversaries may enumerate files and directories.",
			Tactic:      Discovery,
			Platforms:   []string{"Linux", "Windows", "macOS"},
			Detection:   []string{"File access monitoring", "Process command-line monitoring"},
			Mitigation:  []string{"Least privilege", "Network segmentation"},
		},
		{
			ID:          "T1087",
			Name:        "Account Discovery",
			Description: "Adversaries may enumerate accounts to find targets.",
			Tactic:      Discovery,
			Platforms:   []string{"Linux", "Windows", "macOS", "Cloud"},
			Detection:   []string{"Process monitoring", "Command-line logging"},
			Mitigation:  []string{"Least privilege", "Network segmentation"},
		},
		{
			ID:          "T1046",
			Name:        "Network Service Discovery",
			Description: "Adversaries may discover network services and their configurations.",
			Tactic:      Discovery,
			Platforms:   []string{"Linux", "Windows", "macOS"},
			Detection:   []string{"Network traffic monitoring", "Process monitoring"},
			Mitigation:  []string{"Network segmentation", "Disable unnecessary services"},
		},

		// Lateral Movement
		{
			ID:          "T1021",
			Name:        "Remote Services",
			Description: "Adversaries may use remote services to move laterally.",
			Tactic:      LateralMovement,
			Platforms:   []string{"Linux", "Windows", "macOS"},
			Detection:   []string{"Network traffic analysis", "Authentication logs"},
			Mitigation:  []string{"Disable unnecessary services", "MFA", "Network segmentation"},
		},
		{
			ID:          "T1550",
			Name:        "Use Alternate Authentication Material",
			Description: "Adversaries may use alternate authentication material like tokens.",
			Tactic:      LateralMovement,
			Platforms:   []string{"Linux", "Windows", "Cloud"},
			Detection:   []string{"Token usage monitoring", "Anomalous authentication"},
			Mitigation:  []string{"User account control", "Privileged account management"},
		},

		// Collection
		{
			ID:          "T1005",
			Name:        "Data from Local System",
			Description: "Adversaries may search local systems for data.",
			Tactic:      Collection,
			Platforms:   []string{"Linux", "Windows", "macOS"},
			Detection:   []string{"File access monitoring", "Process monitoring"},
			Mitigation:  []string{"Data loss prevention", "Encryption"},
		},
		{
			ID:          "T1113",
			Name:        "Screen Capture",
			Description: "Adversaries may capture screen images.",
			Tactic:      Collection,
			Platforms:   []string{"Linux", "Windows", "macOS"},
			Detection:   []string{"API monitoring", "Process monitoring"},
			Mitigation:  []string{"User training", "Screen protection"},
		},
		{
			ID:          "T1560",
			Name:        "Archive Collected Data",
			Description: "Adversaries may compress or encrypt collected data.",
			Tactic:      Collection,
			Platforms:   []string{"Linux", "Windows", "macOS"},
			Detection:   []string{"File monitoring", "Process monitoring"},
			Mitigation:  []string{"File monitoring", "Data loss prevention"},
		},

		// Exfiltration
		{
			ID:          "T1041",
			Name:        "Exfiltration Over C2 Channel",
			Description: "Adversaries may exfiltrate data over their C2 channel.",
			Tactic:      Exfiltration,
			Platforms:   []string{"Linux", "Windows", "macOS"},
			Detection:   []string{"Network traffic monitoring", "Data loss prevention"},
			Mitigation:  []string{"Network segmentation", "Data loss prevention"},
		},
		{
			ID:          "T1567",
			Name:        "Exfiltration Over Web Service",
			Description: "Adversaries may exfiltrate data to cloud storage.",
			Tactic:      Exfiltration,
			Platforms:   []string{"Linux", "Windows", "macOS"},
			Detection:   []string{"Network monitoring", "Cloud access monitoring"},
			Mitigation:  []string{"Data loss prevention", "Network segmentation"},
		},

		// Command and Control
		{
			ID:          "T1071",
			Name:        "Application Layer Protocol",
			Description: "Adversaries may use application layer protocols for C2.",
			Tactic:      CommandAndControl,
			Platforms:   []string{"Linux", "Windows", "macOS"},
			Detection:   []string{"Network traffic analysis", "Protocol analysis"},
			Mitigation:  []string{"Network intrusion prevention", "SSL/TLS inspection"},
		},
		{
			ID:          "T1573",
			Name:        "Encrypted Channel",
			Description: "Adversaries may use encryption to hide C2 communications.",
			Tactic:      CommandAndControl,
			Platforms:   []string{"Linux", "Windows", "macOS"},
			Detection:   []string{"SSL/TLS inspection", "Traffic pattern analysis"},
			Mitigation:  []string{"SSL/TLS inspection", "Network segmentation"},
		},
		{
			ID:          "T1105",
			Name:        "Ingress Tool Transfer",
			Description: "Adversaries may transfer tools into a compromised environment.",
			Tactic:      CommandAndControl,
			Platforms:   []string{"Linux", "Windows", "macOS"},
			Detection:   []string{"File monitoring", "Network traffic analysis"},
			Mitigation:  []string{"Network intrusion prevention", "Execution prevention"},
		},

		// Impact
		{
			ID:          "T1486",
			Name:        "Data Encrypted for Impact",
			Description: "Adversaries may encrypt data to impact availability (ransomware).",
			Tactic:      Impact,
			Platforms:   []string{"Linux", "Windows", "macOS"},
			Detection:   []string{"File monitoring", "Process monitoring", "Behavior analysis"},
			Mitigation:  []string{"Backups", "Data recovery", "Behavior prevention"},
		},
		{
			ID:          "T1499",
			Name:        "Endpoint Denial of Service",
			Description: "Adversaries may perform DoS attacks against endpoints.",
			Tactic:      Impact,
			Platforms:   []string{"Linux", "Windows", "macOS"},
			Detection:   []string{"Resource monitoring", "Performance degradation"},
			Mitigation:  []string{"Rate limiting", "Resource quotas"},
		},
		{
			ID:          "T1490",
			Name:        "Inhibit System Recovery",
			Description: "Adversaries may delete or modify recovery mechanisms.",
			Tactic:      Impact,
			Platforms:   []string{"Linux", "Windows", "macOS"},
			Detection:   []string{"File monitoring", "Process monitoring"},
			Mitigation:  []string{"Backup protection", "Restrict permissions"},
		},
		{
			ID:          "T1565",
			Name:        "Data Manipulation",
			Description: "Adversaries may manipulate data to impact integrity.",
			Tactic:      Impact,
			Platforms:   []string{"Linux", "Windows", "macOS"},
			Detection:   []string{"File integrity monitoring", "Audit logging"},
			Mitigation:  []string{"Data integrity checks", "Access controls"},
		},
	}
}

// GetTechniqueByID returns a technique by its ID
func GetTechniqueByID(id string) *Technique {
	techniques := AllTechniques()
	for _, tech := range techniques {
		if tech.ID == id {
			return &tech
		}
	}
	return nil
}

// GetTechniquesByTactic returns all techniques for a given tactic
func GetTechniquesByTactic(tactic Tactic) []Technique {
	allTechniques := AllTechniques()
	var result []Technique
	for _, tech := range allTechniques {
		if tech.Tactic == tactic {
			result = append(result, tech)
		}
	}
	return result
}
