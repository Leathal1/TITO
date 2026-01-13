"""
Intelligence Processing Pipeline

The pipeline that transforms raw threats into refined, actionable intelligence.

Collection → Normalization → Enrichment → Deduplication → Prioritization
"""

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Set
import logging

from atip.core.models.threat import Threat, ThreatIndicator


class ThreatPipeline:
    """
    Processing pipeline for threat intelligence

    The nervous system that takes raw signals and produces clarity.
    """

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.logger = logging.getLogger("atip.pipeline")
        self.seen_threats: Dict[str, Threat] = {}  # Deduplication cache
        self.metrics = defaultdict(int)

    def process(self, threats: List[Threat]) -> List[Threat]:
        """
        Process a batch of threats through the pipeline

        Pipeline stages:
        1. Normalize - Ensure consistent data format
        2. Enrich - Add contextual information
        3. Deduplicate - Remove duplicate threats
        4. Prioritize - Calculate priority scores
        5. Filter - Remove noise
        """
        self.logger.info(f"Processing {len(threats)} threats through pipeline")

        # Stage 1: Normalize
        threats = self._normalize(threats)
        self.metrics["normalized"] = len(threats)

        # Stage 2: Enrich
        threats = self._enrich(threats)
        self.metrics["enriched"] = len(threats)

        # Stage 3: Deduplicate
        threats = self._deduplicate(threats)
        self.metrics["deduplicated"] = len(threats)

        # Stage 4: Prioritize
        threats = self._prioritize(threats)
        self.metrics["prioritized"] = len(threats)

        # Stage 5: Filter
        threats = self._filter(threats)
        self.metrics["filtered"] = len(threats)

        self.logger.info(f"Pipeline complete: {len(threats)} threats remain")
        return threats

    def _normalize(self, threats: List[Threat]) -> List[Threat]:
        """
        Normalize threat data

        Ensures consistent formatting, fills in defaults, validates data
        """
        normalized = []

        for threat in threats:
            # Ensure title is not empty
            if not threat.title:
                threat.title = threat.description[:100] if threat.description else "Untitled Threat"

            # Ensure timestamps are set
            if not threat.discovered_at:
                threat.discovered_at = datetime.utcnow()

            if not threat.updated_at:
                threat.updated_at = datetime.utcnow()

            # Normalize tags to lowercase
            threat.tags = {tag.lower() for tag in threat.tags}

            normalized.append(threat)

        return normalized

    def _enrich(self, threats: List[Threat]) -> List[Threat]:
        """
        Enrich threats with additional context

        This is where data becomes intelligence. We add:
        - Asset relevance
        - Exploitation status from external sources
        - Historical context
        - Related threats
        """
        enriched = []

        for threat in threats:
            # Enrichment 1: Check if affects known assets
            # (Real implementation would query asset inventory)
            threat.context.affects_known_assets = self._check_asset_relevance(threat)

            # Enrichment 2: Check exploitation status
            # (Real implementation would query CISA KEV, exploit-db, etc.)
            threat.context.exploitation_status = self._check_exploitation_status(threat)

            # Enrichment 3: Add detection rules based on STRIDE-LM
            if threat.stride_profile:
                detection_strategies = threat.stride_profile.primary_category.detection_strategies
                threat.detection_rules = detection_strategies[:3]  # Top 3

            # Enrichment 4: Cross-reference with known campaigns
            # (Real implementation would check threat intel databases)
            threat.context.known_campaigns = self._check_campaigns(threat)

            enriched.append(threat)

        return enriched

    def _deduplicate(self, threats: List[Threat]) -> List[Threat]:
        """
        Remove duplicate threats

        Deduplication strategy:
        - CVEs: dedupe by CVE ID
        - IOCs: dedupe by indicator value
        - Others: dedupe by title similarity

        When duplicates found, merge into existing threat with updated info
        """
        deduplicated = []
        seen_keys: Set[str] = set()

        for threat in threats:
            # Generate deduplication key
            key = self._generate_dedup_key(threat)

            if key in seen_keys:
                # Duplicate - merge with existing
                self.logger.debug(f"Duplicate threat detected: {threat.title}")
                existing = self._find_threat_by_key(deduplicated, key)
                if existing:
                    self._merge_threats(existing, threat)
                continue

            seen_keys.add(key)
            deduplicated.append(threat)

        dedup_count = len(threats) - len(deduplicated)
        self.logger.info(f"Deduplicated {dedup_count} threats")

        return deduplicated

    def _prioritize(self, threats: List[Threat]) -> List[Threat]:
        """
        Calculate and update priority scores for all threats

        Priority = f(severity, context, urgency, recency)
        """
        for threat in threats:
            threat.update_priority()

        # Sort by priority (highest first)
        threats.sort(key=lambda t: t.priority_score, reverse=True)

        return threats

    def _filter(self, threats: List[Threat]) -> List[Threat]:
        """
        Filter out noise

        Remove threats that don't meet quality thresholds:
        - False positives (marked by analysts)
        - Very low priority threats
        - Too old without updates
        """
        filtered = []

        min_priority = self.config.get("min_priority", 0.2)
        max_age_days = self.config.get("max_age_days", 90)

        for threat in threats:
            # Skip false positives
            if threat.false_positive:
                self.logger.debug(f"Filtered false positive: {threat.title}")
                continue

            # Skip very low priority
            if threat.priority_score < min_priority:
                self.logger.debug(f"Filtered low priority: {threat.title}")
                continue

            # Skip too old
            age_days = (datetime.utcnow() - threat.discovered_at).days
            if age_days > max_age_days:
                self.logger.debug(f"Filtered old threat: {threat.title}")
                continue

            filtered.append(threat)

        filter_count = len(threats) - len(filtered)
        self.logger.info(f"Filtered {filter_count} low-quality threats")

        return filtered

    def _generate_dedup_key(self, threat: Threat) -> str:
        """Generate deduplication key for a threat"""
        # CVEs dedupe by CVE ID
        if threat.cve_ids:
            return f"cve:{threat.cve_ids[0]}"

        # IOCs dedupe by first indicator value
        if threat.indicators:
            ind = threat.indicators[0]
            return f"ioc:{ind.type.value}:{ind.value}"

        # Others dedupe by title
        return f"title:{threat.title[:100]}"

    def _find_threat_by_key(self, threats: List[Threat], key: str) -> Optional[Threat]:
        """Find threat in list by deduplication key"""
        for threat in threats:
            if self._generate_dedup_key(threat) == key:
                return threat
        return None

    def _merge_threats(self, existing: Threat, new: Threat) -> None:
        """Merge new threat data into existing threat"""
        # Update timestamp
        existing.updated_at = datetime.utcnow()

        # Merge indicators
        existing_values = {ind.value for ind in existing.indicators}
        for ind in new.indicators:
            if ind.value not in existing_values:
                existing.indicators.append(ind)

        # Merge tags
        existing.tags.update(new.tags)

        # Merge source feeds
        existing.source_feeds.extend(new.source_feeds)
        existing.source_feeds = list(set(existing.source_feeds))  # Dedupe

        # Take higher severity
        if new.severity.score > existing.severity.score:
            existing.severity = new.severity

        # Recalculate priority
        existing.update_priority()

    def _check_asset_relevance(self, threat: Threat) -> bool:
        """Check if threat affects known assets (stub)"""
        # Real implementation would query asset inventory
        # For now, mark high severity as affecting assets
        return threat.severity.score >= 7

    def _check_exploitation_status(self, threat: Threat):
        """Check exploitation status from external sources (stub)"""
        # Real implementation would check CISA KEV, etc.
        return threat.context.exploitation_status

    def _check_campaigns(self, threat: Threat) -> List[str]:
        """Check if threat is part of known campaigns (stub)"""
        # Real implementation would check threat intel databases
        return []

    def get_metrics(self) -> Dict:
        """Get pipeline metrics"""
        return dict(self.metrics)


from typing import Optional  # Add this import at the top
