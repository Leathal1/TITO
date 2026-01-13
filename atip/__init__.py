"""
ATIP - Advanced Threat Intelligence Platform

An intelligence organism that transforms chaos into actionable clarity.
"""

__version__ = "0.1.0"
__author__ = "ATIP Team"

from atip.core.models.threat import Threat, ThreatIndicator, ThreatContext
from atip.core.stride_lm.classifier import StridelMClassifier
from atip.core.stride_lm.categories import StrideLMCategory

__all__ = [
    "Threat",
    "ThreatIndicator",
    "ThreatContext",
    "StridelMClassifier",
    "StrideLMCategory",
]
