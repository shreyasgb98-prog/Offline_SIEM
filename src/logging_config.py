"""Logging configuration."""

import logging
import sys
from pathlib import Path
from typing import Any, Dict


def setup_logging(config: Dict[str, Any] | None = None) -> logging.Logger:
    """Setup application logging.

    Args:
        config: Optional logging configuration dict. If None, loads from config.yaml.

    Returns:
        Configured root logger.
    """
    # Load config if not provided
    if config is None:
        from src.config import load_config

        full_config = load_config()
        config = full_config.get("logging", {})

    # Get logging settings
    level = config.get("level", "INFO")
    format_str = config.get("format", "%(levelname)s: %(message)s")

    # Configure root logger
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format=format_str,
        handlers=[
            logging.StreamHandler(sys.stdout),
        ],
    )

    logger = logging.getLogger(__name__)
    logger.info(f"Logging initialized at {level} level")

    return logger