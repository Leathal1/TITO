"""
Configuration Management

Sensible defaults. Progressive disclosure. No unnecessary complexity.
"""

import os
from pathlib import Path
from typing import Any, Dict, Optional
import yaml


class Config:
    """
    Configuration manager for ATIP

    Reads from:
    1. Environment variables
    2. Config file (YAML)
    3. Defaults
    """

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or self._default_config_path()
        self.config = self._load_config()

    def _default_config_path(self) -> str:
        """Default configuration file path"""
        # Check environment variable first
        if "ATIP_CONFIG" in os.environ:
            return os.environ["ATIP_CONFIG"]

        # Check current directory
        if os.path.exists("config.yaml"):
            return "config.yaml"

        # Check ~/.atip/config.yaml
        home_config = Path.home() / ".atip" / "config.yaml"
        if home_config.exists():
            return str(home_config)

        # No config file found
        return ""

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        # Start with defaults
        config = self._default_config()

        # Load from file if it exists
        if self.config_path and os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r") as f:
                    file_config = yaml.safe_load(f)
                    if file_config:
                        self._deep_merge(config, file_config)
            except Exception as e:
                print(f"Warning: Failed to load config from {self.config_path}: {e}")

        # Override with environment variables
        self._apply_env_overrides(config)

        return config

    def _default_config(self) -> Dict[str, Any]:
        """Default configuration"""
        return {
            "collectors": {
                "nvd": {
                    "enabled": True,
                    "api_key": None,
                    "days_back": 7,
                    "interval_seconds": 21600,  # 6 hours
                },
                "osint": {
                    "enabled": True,
                    "feeds": [],
                    "interval_seconds": 14400,  # 4 hours
                },
            },
            "pipeline": {
                "min_priority": 0.2,  # Filter threats below this priority
                "max_age_days": 90,  # Filter threats older than this
            },
            "storage": {
                "type": "sqlite",  # sqlite, postgresql, etc.
                "path": "atip.db",
                "connection_string": None,
            },
            "api": {
                "enabled": True,
                "host": "0.0.0.0",
                "port": 8080,
                "cors_enabled": True,
            },
            "logging": {
                "level": "INFO",
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "file": None,  # If set, log to file
            },
            "reports": {
                "output_dir": "reports",
                "formats": ["markdown", "json"],
            },
        }

    def _deep_merge(self, base: Dict, override: Dict) -> None:
        """Deep merge override into base"""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value

    def _apply_env_overrides(self, config: Dict) -> None:
        """Apply environment variable overrides"""
        # NVD API key
        if "NVD_API_KEY" in os.environ:
            config["collectors"]["nvd"]["api_key"] = os.environ["NVD_API_KEY"]

        # Database connection
        if "DATABASE_URL" in os.environ:
            config["storage"]["connection_string"] = os.environ["DATABASE_URL"]

        # API port
        if "ATIP_PORT" in os.environ:
            try:
                config["api"]["port"] = int(os.environ["ATIP_PORT"])
            except ValueError:
                pass

        # Log level
        if "LOG_LEVEL" in os.environ:
            config["logging"]["level"] = os.environ["LOG_LEVEL"].upper()

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value by key

        Supports dot notation: config.get("collectors.nvd.enabled")
        """
        keys = key.split(".")
        value = self.config

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    def set(self, key: str, value: Any) -> None:
        """Set configuration value"""
        keys = key.split(".")
        config = self.config

        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]

        config[keys[-1]] = value

    def save(self, path: Optional[str] = None) -> None:
        """Save configuration to file"""
        save_path = path or self.config_path

        if not save_path:
            raise ValueError("No config path specified")

        # Create directory if needed
        Path(save_path).parent.mkdir(parents=True, exist_ok=True)

        with open(save_path, "w") as f:
            yaml.dump(self.config, f, default_flow_style=False, sort_keys=False)

    def to_dict(self) -> Dict[str, Any]:
        """Get configuration as dictionary"""
        return self.config.copy()


def create_default_config(path: str) -> None:
    """Create a default configuration file"""
    config = Config()
    config.save(path)
    print(f"Created default configuration at {path}")
