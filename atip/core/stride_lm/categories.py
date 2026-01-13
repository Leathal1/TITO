"""
STRIDE-LM Threat Categories

The lens through which we view all threats. Each category represents
a fundamental way systems fail under attack.
"""

from enum import Enum
from typing import Dict, List, Set
from dataclasses import dataclass


class StrideLMCategory(Enum):
    """
    The STRIDE-LM Framework - Extended threat modeling for modern attacks

    Each category answers a fundamental question about the threat:
    - SPOOFING: "Who are you, really?"
    - TAMPERING: "Can I trust what I'm seeing?"
    - REPUDIATION: "Did that really happen?"
    - INFO_DISCLOSURE: "What's escaping?"
    - DENIAL_OF_SERVICE: "Can you still operate?"
    - ELEVATION: "What can they reach now?"
    - LATERAL_MOVEMENT: "Where are they going next?"
    - MALWARE: "What did they leave behind?"
    """

    SPOOFING = "S"
    TAMPERING = "T"
    REPUDIATION = "R"
    INFO_DISCLOSURE = "I"
    DENIAL_OF_SERVICE = "D"
    ELEVATION = "E"
    LATERAL_MOVEMENT = "L"
    MALWARE = "M"

    @property
    def full_name(self) -> str:
        """Human-readable category name"""
        return {
            "S": "Spoofing",
            "T": "Tampering",
            "R": "Repudiation",
            "I": "Information Disclosure",
            "D": "Denial of Service",
            "E": "Elevation of Privilege",
            "L": "Lateral Movement",
            "M": "Malware",
        }[self.value]

    @property
    def question(self) -> str:
        """The fundamental question this category answers"""
        return {
            "S": "Who are you, really?",
            "T": "Can I trust what I'm seeing?",
            "R": "Did that really happen?",
            "I": "What's escaping?",
            "D": "Can you still operate?",
            "E": "What can they reach now?",
            "L": "Where are they going next?",
            "M": "What did they leave behind?",
        }[self.value]

    @property
    def description(self) -> str:
        """Rich description of the threat category"""
        return {
            "S": "Identity is the new perimeter. Credential leaks, auth bypasses, "
                 "token forgery. The attacker wearing your employee's face.",
            "T": "Data integrity is assumed until it isn't. Supply chain attacks, "
                 "injection, MITM. The code you deployed isn't the code running.",
            "R": "Logs are your memory; memory can be erased. Audit gaps, "
                 "timestamp manipulation. The attack you can't prove occurred.",
            "I": "Secrets have gravity; they fall toward exposure. Breaches, "
                 "misconfigs, verbose errors. The data you forgot you were storing.",
            "D": "Availability is a security property. Resource exhaustion, "
                 "amplification, logic DoS. The death by a thousand requests.",
            "E": "Every privilege is a blast radius. Privesc CVEs, misconfigs, "
                 "confused deputies. The janitor with the master key.",
            "L": "Breach is a moment; compromise is a journey. Pivoting, "
                 "credential reuse, trust exploitation. The attacker who's already inside.",
            "M": "Code with hostile intent. Implants, C2, persistence mechanisms. "
                 "The gift that keeps on taking.",
        }[self.value]

    @property
    def impact_areas(self) -> List[str]:
        """Primary areas of impact for this category"""
        return {
            "S": ["Authentication", "Identity", "Access Control", "Trust"],
            "T": ["Data Integrity", "Code Integrity", "Supply Chain", "Trust"],
            "R": ["Audit", "Logging", "Forensics", "Accountability"],
            "I": ["Confidentiality", "Privacy", "Secrets Management", "Data Protection"],
            "D": ["Availability", "Resilience", "Performance", "Operations"],
            "E": ["Authorization", "Privileges", "Access Control", "Blast Radius"],
            "L": ["Network Security", "Segmentation", "Trust Boundaries", "Containment"],
            "M": ["Code Integrity", "Persistence", "Detection", "Response"],
        }[self.value]

    @property
    def detection_strategies(self) -> List[str]:
        """How to detect threats in this category"""
        return {
            "S": [
                "Monitor authentication failures and anomalies",
                "Track credential usage patterns",
                "Validate token integrity and issuance",
                "Correlate identity across systems",
            ],
            "T": [
                "Implement integrity checks and signatures",
                "Monitor for unexpected code/data changes",
                "Verify supply chain provenance",
                "Use runtime application self-protection",
            ],
            "R": [
                "Ensure centralized, immutable logging",
                "Monitor for log deletion or manipulation",
                "Implement clock synchronization",
                "Create audit trails for critical actions",
            ],
            "I": [
                "Monitor outbound data transfers",
                "Implement DLP and secrets detection",
                "Track access to sensitive resources",
                "Alert on misconfiguration exposures",
            ],
            "D": [
                "Monitor resource utilization trends",
                "Implement rate limiting and quotas",
                "Track request patterns for anomalies",
                "Alert on service degradation",
            ],
            "E": [
                "Monitor privilege escalation attempts",
                "Track use of administrative privileges",
                "Alert on unexpected process behavior",
                "Implement least privilege enforcement",
            ],
            "L": [
                "Monitor lateral network movements",
                "Track credential reuse across systems",
                "Alert on unusual access patterns",
                "Implement micro-segmentation",
            ],
            "M": [
                "Deploy endpoint detection and response",
                "Monitor for persistence mechanisms",
                "Track C2 communication patterns",
                "Implement behavioral analysis",
            ],
        }[self.value]

    @property
    def mitigation_strategies(self) -> List[str]:
        """How to mitigate threats in this category"""
        return {
            "S": [
                "Implement MFA across all systems",
                "Use hardware security keys where possible",
                "Enforce certificate-based authentication",
                "Implement passwordless authentication",
            ],
            "T": [
                "Sign all code and data",
                "Implement software bill of materials (SBOM)",
                "Use secure channels for all transfers",
                "Deploy runtime integrity monitoring",
            ],
            "R": [
                "Use write-once logging systems",
                "Implement centralized SIEM",
                "Enable audit logs for all critical systems",
                "Use blockchain for critical audit trails",
            ],
            "I": [
                "Encrypt data at rest and in transit",
                "Implement secrets management systems",
                "Use data classification and DLP",
                "Regular access reviews and least privilege",
            ],
            "D": [
                "Implement rate limiting and backpressure",
                "Use CDN and DDoS protection",
                "Design for graceful degradation",
                "Implement circuit breakers",
            ],
            "E": [
                "Enforce principle of least privilege",
                "Use just-in-time access provisioning",
                "Implement privilege access management",
                "Regular privilege audits and reviews",
            ],
            "L": [
                "Implement network segmentation",
                "Use zero-trust architecture",
                "Enforce explicit trust verification",
                "Monitor and restrict east-west traffic",
            ],
            "M": [
                "Deploy EDR/XDR solutions",
                "Implement application whitelisting",
                "Use behavioral analysis and sandboxing",
                "Regular threat hunting exercises",
            ],
        }[self.value]


@dataclass
class StrideLMProfile:
    """
    A STRIDE-LM profile for a specific threat.

    Threats can map to multiple categories with different confidence scores.
    This captures the multi-dimensional nature of real threats.
    """

    primary_category: StrideLMCategory
    secondary_categories: Set[StrideLMCategory]
    confidence_scores: Dict[StrideLMCategory, float]  # 0.0 to 1.0

    @property
    def all_categories(self) -> Set[StrideLMCategory]:
        """All categories this threat maps to"""
        return {self.primary_category} | self.secondary_categories

    def get_score(self, category: StrideLMCategory) -> float:
        """Get confidence score for a specific category"""
        return self.confidence_scores.get(category, 0.0)

    def __str__(self) -> str:
        """Human-readable representation"""
        primary = self.primary_category.value
        secondary = "".join(cat.value for cat in self.secondary_categories)
        return f"{primary}({secondary})" if secondary else primary


# Keywords and patterns for category classification
CATEGORY_PATTERNS = {
    StrideLMCategory.SPOOFING: {
        "keywords": [
            "authentication", "credential", "identity", "token", "session",
            "phishing", "impersonation", "auth bypass", "spoofing", "forgery",
            "oauth", "saml", "jwt", "password", "login", "username",
        ],
        "cwe_ids": [287, 290, 294, 295, 306, 307, 346, 384, 522, 798],
    },
    StrideLMCategory.TAMPERING: {
        "keywords": [
            "injection", "tampering", "modification", "supply chain", "mitm",
            "integrity", "sql injection", "xss", "csrf", "code injection",
            "path traversal", "file upload", "deserialization", "backdoor",
        ],
        "cwe_ids": [20, 74, 78, 79, 89, 94, 352, 502, 611, 913],
    },
    StrideLMCategory.REPUDIATION: {
        "keywords": [
            "logging", "audit", "repudiation", "forensics", "timestamp",
            "log injection", "audit bypass", "accountability", "traceability",
        ],
        "cwe_ids": [117, 532, 778],
    },
    StrideLMCategory.INFO_DISCLOSURE: {
        "keywords": [
            "disclosure", "exposure", "leak", "breach", "exfiltration",
            "information disclosure", "sensitive data", "confidentiality",
            "privacy", "secrets", "credentials", "pii", "directory traversal",
        ],
        "cwe_ids": [22, 200, 209, 215, 312, 319, 326, 327, 359, 532, 538],
    },
    StrideLMCategory.DENIAL_OF_SERVICE: {
        "keywords": [
            "dos", "ddos", "denial of service", "resource exhaustion",
            "amplification", "flood", "cpu", "memory", "regex", "algorithmic complexity",
        ],
        "cwe_ids": [400, 404, 770, 776, 834, 835],
    },
    StrideLMCategory.ELEVATION: {
        "keywords": [
            "privilege escalation", "elevation", "privesc", "root", "admin",
            "sudo", "setuid", "capabilities", "authorization", "access control",
        ],
        "cwe_ids": [269, 274, 277, 278, 282, 283, 284, 285, 862, 863],
    },
    StrideLMCategory.LATERAL_MOVEMENT: {
        "keywords": [
            "lateral movement", "pivoting", "network traversal", "smb", "rdp",
            "pass the hash", "credential reuse", "east-west", "internal network",
        ],
        "cwe_ids": [653],
    },
    StrideLMCategory.MALWARE: {
        "keywords": [
            "malware", "trojan", "backdoor", "c2", "command and control",
            "ransomware", "rootkit", "persistence", "implant", "remote access",
            "cryptominer", "botnet", "rat", "apt",
        ],
        "cwe_ids": [506, 912],
    },
}
