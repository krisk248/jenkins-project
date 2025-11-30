"""Configuration management for ttssecure."""

from .loader import load_config, Config
from .validator import validate_config

__all__ = ["load_config", "Config", "validate_config"]
