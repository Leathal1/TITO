"""
Base collector interface

Collectors breathe in chaos from the wild and transform it into
structured threat intelligence.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Optional
import logging

from atip.core.models.threat import Threat


class CollectorError(Exception):
    """Base exception for collector errors"""

    pass


class BaseCollector(ABC):
    """
    Abstract base class for threat intelligence collectors

    Every collector must:
    1. Know its source
    2. Fetch raw data
    3. Transform it into Threat objects
    4. Handle failures gracefully
    """

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.name = self.__class__.__name__
        self.logger = logging.getLogger(f"atip.collectors.{self.name}")
        self.last_run: Optional[datetime] = None
        self.errors: List[str] = []

    @property
    @abstractmethod
    def source_name(self) -> str:
        """Human-readable name of the intelligence source"""
        pass

    @abstractmethod
    def fetch(self) -> List[Dict]:
        """
        Fetch raw data from the source

        Returns:
            List of raw data dictionaries
        """
        pass

    @abstractmethod
    def parse(self, raw_data: Dict) -> Optional[Threat]:
        """
        Parse raw data into a Threat object

        Args:
            raw_data: Single raw data dictionary from fetch()

        Returns:
            Threat object or None if parsing fails
        """
        pass

    def collect(self) -> List[Threat]:
        """
        Main collection workflow

        This is the orchestration method that:
        1. Fetches raw data
        2. Parses each item
        3. Handles errors gracefully
        4. Returns processed threats

        Returns:
            List of Threat objects
        """
        self.logger.info(f"Starting collection from {self.source_name}")
        self.errors = []
        threats = []

        try:
            # Fetch raw data
            raw_items = self.fetch()
            self.logger.info(f"Fetched {len(raw_items)} raw items from {self.source_name}")

            # Parse each item
            for i, raw_item in enumerate(raw_items):
                try:
                    threat = self.parse(raw_item)
                    if threat:
                        threat.source_feeds.append(self.source_name)
                        threats.append(threat)
                except Exception as e:
                    error_msg = f"Failed to parse item {i}: {str(e)}"
                    self.logger.error(error_msg)
                    self.errors.append(error_msg)
                    continue

            self.last_run = datetime.utcnow()
            self.logger.info(
                f"Collection complete: {len(threats)} threats from {self.source_name}"
            )

        except Exception as e:
            error_msg = f"Collection failed: {str(e)}"
            self.logger.error(error_msg)
            self.errors.append(error_msg)
            raise CollectorError(error_msg) from e

        return threats

    def get_status(self) -> Dict:
        """Get collector status and statistics"""
        return {
            "name": self.name,
            "source": self.source_name,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "errors": self.errors,
            "error_count": len(self.errors),
        }


class ScheduledCollector(BaseCollector):
    """
    Collector that runs on a schedule

    Use this for periodic polling of feeds.
    """

    @property
    @abstractmethod
    def interval_seconds(self) -> int:
        """How often to run this collector (in seconds)"""
        pass

    def should_run(self) -> bool:
        """Check if enough time has passed since last run"""
        if not self.last_run:
            return True

        elapsed = (datetime.utcnow() - self.last_run).total_seconds()
        return elapsed >= self.interval_seconds


class StreamingCollector(BaseCollector):
    """
    Collector that processes streaming data

    Use this for real-time feeds or webhooks.
    """

    @abstractmethod
    def start_stream(self) -> None:
        """Start listening to the stream"""
        pass

    @abstractmethod
    def stop_stream(self) -> None:
        """Stop listening to the stream"""
        pass
