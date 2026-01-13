"""
OSINT (Open Source Intelligence) Collector

Aggregates threat intelligence from open source feeds.
"""

from datetime import datetime
from typing import Dict, List, Optional

from atip.collectors.base import ScheduledCollector
from atip.core.models.threat import (
    Threat,
    ThreatIndicator,
    ThreatContext,
    ThreatSeverity,
    IndicatorType,
)
from atip.core.stride_lm.classifier import StridelMClassifier


class OSINTCollector(ScheduledCollector):
    """
    Collects threat intelligence from OSINT sources

    Sources include:
    - Abuse.ch feeds (malware hashes, C2 IPs)
    - AlienVault OTX
    - ThreatFox
    - URLhaus
    - etc.

    This is a skeleton implementation showing the pattern.
    """

    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        self.feeds = self.config.get("osint_feeds", [])
        self.classifier = StridelMClassifier()

    @property
    def source_name(self) -> str:
        return "OSINT"

    @property
    def interval_seconds(self) -> int:
        """Run every 4 hours"""
        return 4 * 60 * 60

    def fetch(self) -> List[Dict]:
        """
        Fetch from OSINT feeds

        Real implementation would make HTTP requests to various feeds
        """
        # Mock data for demonstration
        return [
            {
                "type": "malware_hash",
                "indicator": "a1b2c3d4e5f6...",
                "malware_family": "Emotet",
                "first_seen": "2024-01-12T10:00:00Z",
                "source": "abuse.ch",
                "description": "Emotet malware sample distributing via phishing campaigns",
            },
            {
                "type": "c2_ip",
                "indicator": "192.0.2.100",
                "port": 443,
                "protocol": "https",
                "first_seen": "2024-01-12T11:00:00Z",
                "source": "threatfox",
                "description": "Command and control server for AsyncRAT",
            },
        ]

    def parse(self, raw_data: Dict) -> Optional[Threat]:
        """Parse OSINT feed data into Threat"""
        try:
            indicator_type_map = {
                "malware_hash": IndicatorType.FILE_HASH,
                "c2_ip": IndicatorType.IP_ADDRESS,
                "domain": IndicatorType.DOMAIN,
                "url": IndicatorType.URL,
            }

            ind_type = indicator_type_map.get(
                raw_data.get("type"), IndicatorType.IP_ADDRESS
            )

            indicator = ThreatIndicator(
                type=ind_type,
                value=raw_data.get("indicator", ""),
                description=raw_data.get("description", ""),
                confidence=0.8,  # OSINT typically high confidence
                source=raw_data.get("source", "OSINT"),
                raw_data=raw_data,
            )

            # Classify
            description = raw_data.get("description", "")
            stride_profile = self.classifier.classify(text=description)

            # Context
            context = ThreatContext()
            context.exploitation_status = (
                raw_data.get("exploitation_status", "active").lower()
            )

            threat = Threat(
                title=f"OSINT: {description[:100]}",
                description=description,
                severity=ThreatSeverity.HIGH,  # OSINT IOCs are typically active threats
                stride_profile=stride_profile,
                indicators=[indicator],
                context=context,
                tags={"osint", raw_data.get("type", "unknown")},
            )

            threat.update_priority()
            return threat

        except Exception as e:
            self.logger.error(f"Failed to parse OSINT data: {str(e)}")
            return None
