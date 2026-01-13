"""
NVD (National Vulnerability Database) Collector

Collects CVE data from the NVD API and transforms it into actionable intelligence.
"""

import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import logging

from atip.collectors.base import ScheduledCollector, CollectorError
from atip.core.models.threat import (
    Threat,
    ThreatIndicator,
    ThreatContext,
    ThreatSeverity,
    IndicatorType,
    ExploitationStatus,
)
from atip.core.stride_lm.classifier import StridelMClassifier


class NVDCollector(ScheduledCollector):
    """
    Collects CVE data from NVD

    NVD is authoritative for CVEs, but the data is raw. Our job is to
    transform it into intelligence that defenders can act on.
    """

    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        self.api_key = self.config.get("nvd_api_key")
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.days_back = self.config.get("days_back", 7)  # How far back to look
        self.classifier = StridelMClassifier()

        # Rate limiting
        self.requests_per_minute = 5 if self.api_key else 5
        self.last_request_time: Optional[datetime] = None

    @property
    def source_name(self) -> str:
        return "NVD"

    @property
    def interval_seconds(self) -> int:
        """Run every 6 hours"""
        return 6 * 60 * 60

    def fetch(self) -> List[Dict]:
        """
        Fetch CVE data from NVD API

        NOTE: This is a simplified implementation. Real implementation would:
        - Handle pagination
        - Implement proper rate limiting
        - Use requests library with retries
        - Cache responses
        """
        self.logger.info(f"Fetching CVEs from last {self.days_back} days")

        # For demonstration, return mock data
        # Real implementation would make API calls
        mock_cves = self._get_mock_cves()

        return mock_cves

    def _get_mock_cves(self) -> List[Dict]:
        """
        Mock CVE data for demonstration

        Real implementation would call NVD API
        """
        return [
            {
                "cve": {
                    "id": "CVE-2024-1234",
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "SQL injection vulnerability in Apache Example 2.4.x allows "
                            "remote attackers to execute arbitrary SQL commands via crafted input.",
                        }
                    ],
                    "published": "2024-01-10T12:00:00.000",
                    "lastModified": "2024-01-10T12:00:00.000",
                    "vulnStatus": "Analyzed",
                    "references": [
                        {"url": "https://example.com/advisory/CVE-2024-1234"}
                    ],
                    "weaknesses": [{"description": [{"value": "CWE-89"}]}],
                },
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            }
                        }
                    ]
                },
            },
            {
                "cve": {
                    "id": "CVE-2024-5678",
                    "descriptions": [
                        {
                            "lang": "en",
                            "value": "Authentication bypass in Login Manager allows unauthorized access",
                        }
                    ],
                    "published": "2024-01-12T08:00:00.000",
                    "lastModified": "2024-01-12T08:00:00.000",
                    "vulnStatus": "Analyzed",
                    "references": [
                        {"url": "https://example.com/advisory/CVE-2024-5678"}
                    ],
                    "weaknesses": [{"description": [{"value": "CWE-287"}]}],
                },
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 8.1,
                                "baseSeverity": "HIGH",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            }
                        }
                    ]
                },
            },
        ]

    def parse(self, raw_data: Dict) -> Optional[Threat]:
        """
        Transform raw NVD data into a Threat object

        This is where raw data becomes intelligence.
        """
        try:
            cve = raw_data.get("cve", {})
            cve_id = cve.get("id", "UNKNOWN")

            # Extract description
            descriptions = cve.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # Extract CVSS metrics
            metrics = raw_data.get("metrics", {})
            cvss_v31 = metrics.get("cvssMetricV31", [{}])[0]
            cvss_data = cvss_v31.get("cvssData", {})

            base_score = cvss_data.get("baseScore", 0.0)
            severity_str = cvss_data.get("baseSeverity", "MEDIUM").lower()
            vector_string = cvss_data.get("vectorString", "")

            # Map CVSS severity to our ThreatSeverity
            severity_mapping = {
                "critical": ThreatSeverity.CRITICAL,
                "high": ThreatSeverity.HIGH,
                "medium": ThreatSeverity.MEDIUM,
                "low": ThreatSeverity.LOW,
                "none": ThreatSeverity.INFO,
            }
            severity = severity_mapping.get(severity_str, ThreatSeverity.MEDIUM)

            # Extract CWE IDs
            cwe_ids = []
            weaknesses = cve.get("weaknesses", [])
            for weakness in weaknesses:
                for desc in weakness.get("description", []):
                    cwe_value = desc.get("value", "")
                    # Extract CWE number (e.g., "CWE-89" -> 89)
                    match = re.search(r"CWE-(\d+)", cwe_value)
                    if match:
                        cwe_ids.append(int(match.group(1)))

            # Parse CVSS vector for context
            context = self._parse_cvss_vector(vector_string, cve_id)

            # Create threat indicator
            indicator = ThreatIndicator(
                type=IndicatorType.CVE,
                value=cve_id,
                description=description,
                confidence=1.0,  # NVD is authoritative
                source="NVD",
                raw_data=raw_data,
            )

            # Classify using STRIDE-LM
            classification_text = f"{cve_id} {description}"
            stride_profile = self.classifier.classify(
                text=classification_text,
                cve_id=cve_id,
                cwe_ids=cwe_ids,
            )

            # Extract references
            references = []
            for ref in cve.get("references", []):
                url = ref.get("url", "")
                if url:
                    references.append(url)

            # Create threat
            threat = Threat(
                title=f"{cve_id}: {description[:100]}",
                description=description,
                severity=severity,
                stride_profile=stride_profile,
                indicators=[indicator],
                context=context,
                cve_ids=[cve_id],
                references=references,
                discovered_at=datetime.utcnow(),
                published_at=self._parse_timestamp(cve.get("published")),
                tags={severity_str, "cve", "nvd"},
            )

            # Generate recommendations based on STRIDE-LM classification
            threat.recommended_actions = self._generate_recommendations(
                stride_profile, severity, cve_id
            )

            # Calculate priority
            threat.update_priority()

            return threat

        except Exception as e:
            self.logger.error(f"Failed to parse CVE data: {str(e)}")
            return None

    def _parse_cvss_vector(self, vector_string: str, cve_id: str) -> ThreatContext:
        """
        Parse CVSS vector string into ThreatContext

        CVSS vectors contain rich contextual information that we extract
        to make prioritization decisions.

        Example: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
        """
        context = ThreatContext()

        if not vector_string:
            return context

        # Parse vector components
        components = {}
        for part in vector_string.split("/"):
            if ":" in part:
                key, value = part.split(":", 1)
                components[key] = value

        # Attack Vector (AV)
        av = components.get("AV", "")
        if av == "N":  # Network
            context.exposure_level = "internet"
            context.affects_known_assets = True  # Network-accessible is always a concern
        elif av == "A":  # Adjacent Network
            context.exposure_level = "internal"
        elif av in ["L", "P"]:  # Local or Physical
            context.exposure_level = "isolated"

        # Attack Complexity (AC)
        ac = components.get("AC", "")
        context.attack_complexity = "low" if ac == "L" else "high"

        # Privileges Required (PR)
        pr = components.get("PR", "")
        context.privileges_required = {"N": "none", "L": "low", "H": "high"}.get(
            pr, "unknown"
        )

        # User Interaction (UI)
        ui = components.get("UI", "")
        context.user_interaction_required = ui == "R"  # Required

        # Impact metrics help determine severity
        c_impact = components.get("C", "")  # Confidentiality
        i_impact = components.get("I", "")  # Integrity
        a_impact = components.get("A", "")  # Availability

        # For now, mark exploitation status as unknown
        # Real implementation would check CISA KEV, exploit-db, etc.
        context.exploitation_status = ExploitationStatus.UNKNOWN

        return context

    def _generate_recommendations(
        self, stride_profile, severity: ThreatSeverity, cve_id: str
    ) -> List[str]:
        """
        Generate actionable recommendations based on STRIDE-LM profile

        This is where we go from "here's a vulnerability" to "here's what to do"
        """
        recommendations = []

        # General recommendations based on severity
        if severity in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH]:
            recommendations.append(
                "URGENT: Prioritize patching immediately. This is a critical vulnerability."
            )
            recommendations.append(
                "Check for indicators of compromise in logs from the last 90 days."
            )

        # STRIDE-LM specific recommendations
        primary_cat = stride_profile.primary_category
        recommendations.extend(primary_cat.mitigation_strategies[:2])  # Top 2

        # Add generic CVE actions
        recommendations.append(f"Review NVD advisory for {cve_id} for full details.")
        recommendations.append("Validate patches in staging before production deployment.")

        return recommendations

    def _parse_timestamp(self, timestamp_str: Optional[str]) -> Optional[datetime]:
        """Parse NVD timestamp format"""
        if not timestamp_str:
            return None

        try:
            # NVD format: "2024-01-10T12:00:00.000"
            return datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except Exception:
            return None
