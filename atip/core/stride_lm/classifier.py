"""
STRIDE-LM Classification Engine

This is the lens through which all threats are viewed.
Not just classification—understanding.
"""

import re
from typing import Dict, List, Optional, Set, Tuple

from atip.core.stride_lm.categories import (
    CATEGORY_PATTERNS,
    StrideLMCategory,
    StrideLMProfile,
)


class StridelMClassifier:
    """
    Classifies threats using the STRIDE-LM framework

    This isn't just keyword matching. It's understanding the nature of the threat
    and mapping it to how defenders think about security.
    """

    def __init__(self):
        self.patterns = CATEGORY_PATTERNS
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Pre-compile regex patterns for efficiency"""
        self.regex_patterns: Dict[StrideLMCategory, List[re.Pattern]] = {}

        for category, data in self.patterns.items():
            patterns = []
            for keyword in data["keywords"]:
                # Match whole words, case insensitive
                pattern = re.compile(r"\b" + re.escape(keyword) + r"\b", re.IGNORECASE)
                patterns.append(pattern)
            self.regex_patterns[category] = patterns

    def classify(
        self,
        text: str,
        cve_id: Optional[str] = None,
        cwe_ids: Optional[List[int]] = None,
        mitre_attack_ids: Optional[List[str]] = None,
        context: Optional[Dict] = None,
    ) -> StrideLMProfile:
        """
        Classify a threat into STRIDE-LM categories

        Args:
            text: Description of the threat (title + description)
            cve_id: CVE identifier if applicable
            cwe_ids: List of CWE IDs associated with the threat
            mitre_attack_ids: List of MITRE ATT&CK technique IDs
            context: Additional context for classification

        Returns:
            StrideLMProfile with primary and secondary categories
        """
        # Calculate confidence scores for each category
        scores = self._calculate_scores(text, cve_id, cwe_ids, mitre_attack_ids, context)

        # Determine primary and secondary categories
        sorted_categories = sorted(scores.items(), key=lambda x: x[1], reverse=True)

        # Primary category is the highest scoring
        primary_category = sorted_categories[0][0]

        # Secondary categories are those with score > threshold
        secondary_threshold = 0.3
        secondary_categories = {
            cat for cat, score in sorted_categories[1:] if score >= secondary_threshold
        }

        return StrideLMProfile(
            primary_category=primary_category,
            secondary_categories=secondary_categories,
            confidence_scores=scores,
        )

    def _calculate_scores(
        self,
        text: str,
        cve_id: Optional[str],
        cwe_ids: Optional[List[int]],
        mitre_attack_ids: Optional[List[str]],
        context: Optional[Dict],
    ) -> Dict[StrideLMCategory, float]:
        """
        Calculate confidence scores for each STRIDE-LM category

        Uses multiple signals:
        - Keyword matching in text
        - CWE ID mapping
        - MITRE ATT&CK technique mapping
        - Contextual heuristics
        """
        scores: Dict[StrideLMCategory, float] = {cat: 0.0 for cat in StrideLMCategory}

        # Signal 1: Keyword matching (weight: 0.4)
        keyword_scores = self._score_keywords(text)
        for cat, score in keyword_scores.items():
            scores[cat] += 0.4 * score

        # Signal 2: CWE ID mapping (weight: 0.3)
        if cwe_ids:
            cwe_scores = self._score_cwe_ids(cwe_ids)
            for cat, score in cwe_scores.items():
                scores[cat] += 0.3 * score

        # Signal 3: MITRE ATT&CK mapping (weight: 0.2)
        if mitre_attack_ids:
            attack_scores = self._score_mitre_attack(mitre_attack_ids)
            for cat, score in attack_scores.items():
                scores[cat] += 0.2 * score

        # Signal 4: Contextual heuristics (weight: 0.1)
        if context:
            context_scores = self._score_context(context)
            for cat, score in context_scores.items():
                scores[cat] += 0.1 * score

        # Normalize scores to 0-1 range
        max_score = max(scores.values()) if scores.values() else 1.0
        if max_score > 0:
            scores = {cat: score / max_score for cat, score in scores.items()}

        # Ensure at least one category has a minimum score
        if all(score < 0.1 for score in scores.values()):
            # Default to INFO_DISCLOSURE for unknown threats
            scores[StrideLMCategory.INFO_DISCLOSURE] = 0.5

        return scores

    def _score_keywords(self, text: str) -> Dict[StrideLMCategory, float]:
        """Score categories based on keyword matches"""
        scores: Dict[StrideLMCategory, float] = {}

        for category, patterns in self.regex_patterns.items():
            matches = 0
            for pattern in patterns:
                if pattern.search(text):
                    matches += 1

            # Score is proportional to number of keyword matches
            # Multiple matches increase confidence
            if matches > 0:
                scores[category] = min(1.0, matches / 3.0)  # Cap at 3 matches
            else:
                scores[category] = 0.0

        return scores

    def _score_cwe_ids(self, cwe_ids: List[int]) -> Dict[StrideLMCategory, float]:
        """Score categories based on CWE ID mappings"""
        scores: Dict[StrideLMCategory, float] = {cat: 0.0 for cat in StrideLMCategory}

        for category, data in self.patterns.items():
            matching_cwes = set(cwe_ids) & set(data.get("cwe_ids", []))
            if matching_cwes:
                # Strong signal - CWE IDs are authoritative
                scores[category] = 1.0

        return scores

    def _score_mitre_attack(
        self, mitre_attack_ids: List[str]
    ) -> Dict[StrideLMCategory, float]:
        """
        Score categories based on MITRE ATT&CK technique mappings

        MITRE ATT&CK tactics map naturally to STRIDE-LM categories
        """
        scores: Dict[StrideLMCategory, float] = {cat: 0.0 for cat in StrideLMCategory}

        # Map ATT&CK tactics to STRIDE-LM categories
        tactic_mapping = {
            "TA0001": StrideLMCategory.SPOOFING,  # Initial Access
            "TA0002": StrideLMCategory.MALWARE,  # Execution
            "TA0003": StrideLMCategory.MALWARE,  # Persistence
            "TA0004": StrideLMCategory.ELEVATION,  # Privilege Escalation
            "TA0005": StrideLMCategory.TAMPERING,  # Defense Evasion
            "TA0006": StrideLMCategory.SPOOFING,  # Credential Access
            "TA0007": StrideLMCategory.LATERAL_MOVEMENT,  # Discovery
            "TA0008": StrideLMCategory.LATERAL_MOVEMENT,  # Lateral Movement
            "TA0009": StrideLMCategory.INFO_DISCLOSURE,  # Collection
            "TA0010": StrideLMCategory.INFO_DISCLOSURE,  # Exfiltration
            "TA0011": StrideLMCategory.MALWARE,  # Command and Control
            "TA0040": StrideLMCategory.DENIAL_OF_SERVICE,  # Impact
        }

        for attack_id in mitre_attack_ids:
            # Extract tactic from technique ID (e.g., T1055 -> TA0004)
            # This is a simplified mapping; real implementation would use ATT&CK data
            for tactic, category in tactic_mapping.items():
                if attack_id.startswith("TA"):
                    if attack_id in tactic_mapping:
                        scores[tactic_mapping[attack_id]] = 0.8

        return scores

    def _score_context(self, context: Dict) -> Dict[StrideLMCategory, float]:
        """Score categories based on contextual information"""
        scores: Dict[StrideLMCategory, float] = {cat: 0.0 for cat in StrideLMCategory}

        # Authentication-related context
        if context.get("requires_authentication") is False:
            scores[StrideLMCategory.SPOOFING] += 0.5

        # Network-related context
        if context.get("network_accessible"):
            scores[StrideLMCategory.LATERAL_MOVEMENT] += 0.3

        # Data exposure context
        if context.get("data_exposure"):
            scores[StrideLMCategory.INFO_DISCLOSURE] += 0.7

        # Service disruption context
        if context.get("affects_availability"):
            scores[StrideLMCategory.DENIAL_OF_SERVICE] += 0.6

        # Privilege context
        if context.get("privilege_escalation"):
            scores[StrideLMCategory.ELEVATION] += 0.8

        return scores

    def explain_classification(self, profile: StrideLMProfile, text: str) -> str:
        """
        Generate human-readable explanation of classification

        This is for analyst transparency—they should understand WHY
        the system classified a threat the way it did.
        """
        lines = []

        primary = profile.primary_category
        lines.append(f"Primary Category: {primary.full_name}")
        lines.append(f"  Question: {primary.question}")
        lines.append(f"  Confidence: {profile.get_score(primary):.2f}")
        lines.append("")

        if profile.secondary_categories:
            lines.append("Secondary Categories:")
            for cat in profile.secondary_categories:
                lines.append(f"  - {cat.full_name} (confidence: {profile.get_score(cat):.2f})")
            lines.append("")

        lines.append("Detection Strategies:")
        for strategy in primary.detection_strategies:
            lines.append(f"  • {strategy}")
        lines.append("")

        lines.append("Mitigation Strategies:")
        for strategy in primary.mitigation_strategies:
            lines.append(f"  • {strategy}")

        return "\n".join(lines)

    def batch_classify(
        self, threats: List[Tuple[str, Dict]]
    ) -> List[StrideLMProfile]:
        """
        Classify multiple threats efficiently

        Args:
            threats: List of (text, metadata) tuples

        Returns:
            List of StrideLMProfile objects
        """
        profiles = []
        for text, metadata in threats:
            profile = self.classify(
                text=text,
                cve_id=metadata.get("cve_id"),
                cwe_ids=metadata.get("cwe_ids"),
                mitre_attack_ids=metadata.get("mitre_attack_ids"),
                context=metadata.get("context"),
            )
            profiles.append(profile)
        return profiles
