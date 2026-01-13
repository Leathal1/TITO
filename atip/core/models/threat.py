"""
Core threat data models

Intelligence, not data. Every field serves a purpose.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set
from uuid import uuid4

from atip.core.stride_lm.categories import StrideLMCategory, StrideLMProfile


class ThreatSeverity(Enum):
    """
    Threat severity levels

    CRITICAL: Active exploitation, widespread, high impact
    HIGH: High likelihood or high impact
    MEDIUM: Moderate risk
    LOW: Limited impact or low likelihood
    INFO: Informational, awareness only
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def score(self) -> int:
        """Numeric score for sorting (higher = more severe)"""
        return {"critical": 10, "high": 7, "medium": 5, "low": 3, "info": 1}[self.value]


class IndicatorType(Enum):
    """Types of threat indicators"""

    CVE = "cve"  # CVE vulnerability
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"  # MD5, SHA1, SHA256
    EMAIL = "email"
    MALWARE_SIGNATURE = "malware_signature"
    YARA_RULE = "yara_rule"
    ATTACK_PATTERN = "attack_pattern"  # MITRE ATT&CK
    EXPLOIT = "exploit"
    TOOL = "tool"  # Attack tools/frameworks


class ExploitationStatus(Enum):
    """Status of exploitation in the wild"""

    ACTIVE = "active"  # Currently being exploited
    POC_PUBLIC = "poc_public"  # PoC available publicly
    WEAPONIZED = "weaponized"  # Exploit code exists but not widely used
    THEORETICAL = "theoretical"  # No known exploitation
    UNKNOWN = "unknown"


@dataclass
class ThreatIndicator:
    """
    A single indicator of compromise or threat signal

    This is the atomic unit of threat intelligence.
    """

    id: str = field(default_factory=lambda: str(uuid4()))
    type: IndicatorType = IndicatorType.CVE
    value: str = ""  # The actual indicator (CVE-ID, IP, hash, etc.)
    description: str = ""
    confidence: float = 0.0  # 0.0 to 1.0
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    tags: Set[str] = field(default_factory=set)
    source: str = ""  # Where this indicator came from
    raw_data: Dict = field(default_factory=dict)  # Original data


@dataclass
class ThreatContext:
    """
    Contextual information that transforms data into intelligence

    This is what separates "here's a CVE" from "here's why this matters to YOU"
    """

    # Asset relevance
    affects_known_assets: bool = False
    affected_asset_types: Set[str] = field(default_factory=set)  # web, database, etc.
    affected_technologies: Set[str] = field(default_factory=set)  # nginx, postgresql, etc.

    # Attack surface
    exposure_level: str = "unknown"  # internet, internal, isolated
    attack_complexity: str = "unknown"  # low, medium, high
    user_interaction_required: bool = True
    privileges_required: str = "high"  # none, low, high

    # Intelligence enrichment
    exploitation_status: ExploitationStatus = ExploitationStatus.UNKNOWN
    exploit_maturity: str = "unknown"  # unproven, poc, functional, high
    known_campaigns: List[str] = field(default_factory=list)  # APT groups, campaigns
    threat_actor_attribution: List[str] = field(default_factory=list)

    # Historical
    similar_incidents_count: int = 0
    historical_impact: List[str] = field(default_factory=list)

    # Mitigation
    mitigation_available: bool = False
    patch_available: bool = False
    workaround_available: bool = False
    mitigation_complexity: str = "unknown"  # low, medium, high

    def calculate_urgency_score(self) -> float:
        """
        Calculate urgency score (0.0 to 1.0)

        The answer to: "How fast should we respond?"
        """
        score = 0.0

        # Exploitation status is critical
        exploitation_weight = {
            ExploitationStatus.ACTIVE: 0.4,
            ExploitationStatus.WEAPONIZED: 0.3,
            ExploitationStatus.POC_PUBLIC: 0.2,
            ExploitationStatus.THEORETICAL: 0.05,
            ExploitationStatus.UNKNOWN: 0.1,
        }
        score += exploitation_weight.get(self.exploitation_status, 0.1)

        # Asset relevance
        if self.affects_known_assets:
            score += 0.25

        # Exposure
        exposure_weight = {"internet": 0.2, "internal": 0.1, "isolated": 0.05}
        score += exposure_weight.get(self.exposure_level, 0.1)

        # Attack complexity (lower is worse)
        complexity_weight = {"low": 0.15, "medium": 0.08, "high": 0.03}
        score += complexity_weight.get(self.attack_complexity, 0.05)

        return min(score, 1.0)


@dataclass
class Threat:
    """
    A threat intelligence entry

    This is intelligence, not data. Every threat that reaches a human
    should deserve to reach a human.
    """

    id: str = field(default_factory=lambda: str(uuid4()))
    title: str = ""
    description: str = ""
    severity: ThreatSeverity = ThreatSeverity.MEDIUM

    # STRIDE-LM classification
    stride_profile: Optional[StrideLMProfile] = None

    # Indicators
    indicators: List[ThreatIndicator] = field(default_factory=list)

    # Context (this is what makes it intelligence)
    context: ThreatContext = field(default_factory=ThreatContext)

    # Temporal
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    published_at: Optional[datetime] = None
    updated_at: datetime = field(default_factory=datetime.utcnow)

    # References
    references: List[str] = field(default_factory=list)  # URLs to advisories, etc.
    cve_ids: List[str] = field(default_factory=list)
    mitre_attack_ids: List[str] = field(default_factory=list)  # T1055, etc.

    # Recommendations
    recommended_actions: List[str] = field(default_factory=list)
    detection_rules: List[str] = field(default_factory=list)

    # Metadata
    tags: Set[str] = field(default_factory=set)
    priority_score: float = 0.0  # Calculated score (0.0 to 1.0)

    # Tracking
    source_feeds: List[str] = field(default_factory=list)
    analyst_notes: str = ""
    false_positive: bool = False

    def calculate_priority_score(self) -> float:
        """
        Calculate priority score (0.0 to 1.0)

        The answer to: "Should I care about this threat RIGHT NOW?"

        Combines severity, context, and urgency into a single score
        that helps analysts focus on what matters.
        """
        # Base score from severity
        severity_weight = 0.3
        severity_score = self.severity.score / 10.0

        # Urgency from context
        urgency_weight = 0.4
        urgency_score = self.context.calculate_urgency_score()

        # STRIDE-LM categories add nuance
        stride_weight = 0.2
        stride_score = 0.5  # Default
        if self.stride_profile:
            # Higher confidence = higher score
            avg_confidence = sum(self.stride_profile.confidence_scores.values()) / max(
                len(self.stride_profile.confidence_scores), 1
            )
            stride_score = avg_confidence

        # Recency matters
        recency_weight = 0.1
        age_days = (datetime.utcnow() - self.discovered_at).days
        recency_score = max(0.0, 1.0 - (age_days / 30.0))  # Decay over 30 days

        total_score = (
            severity_weight * severity_score
            + urgency_weight * urgency_score
            + stride_weight * stride_score
            + recency_weight * recency_score
        )

        return min(total_score, 1.0)

    def update_priority(self) -> None:
        """Recalculate and update priority score"""
        self.priority_score = self.calculate_priority_score()
        self.updated_at = datetime.utcnow()

    def add_indicator(self, indicator: ThreatIndicator) -> None:
        """Add an indicator and update timestamp"""
        self.indicators.append(indicator)
        self.updated_at = datetime.utcnow()

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "stride_profile": str(self.stride_profile) if self.stride_profile else None,
            "indicators": [
                {
                    "type": ind.type.value,
                    "value": ind.value,
                    "confidence": ind.confidence,
                }
                for ind in self.indicators
            ],
            "priority_score": self.priority_score,
            "cve_ids": self.cve_ids,
            "mitre_attack_ids": self.mitre_attack_ids,
            "recommended_actions": self.recommended_actions,
            "discovered_at": self.discovered_at.isoformat(),
            "tags": list(self.tags),
        }

    def __str__(self) -> str:
        """Human-readable representation"""
        stride = f" [{self.stride_profile}]" if self.stride_profile else ""
        return f"[{self.severity.value.upper()}]{stride} {self.title}"
