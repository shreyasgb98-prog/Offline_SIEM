"""Configuration loader."""

import logging
from pathlib import Path
from typing import Any, Dict

import yaml


def load_config(config_path: str | None = None) -> Dict[str, Any]:
    """Load configuration from YAML file.

    Args:
        config_path: Path to config file. Defaults to config.yaml in project root.

    Returns:
        Configuration dictionary.

    Raises:
        FileNotFoundError: If config file not found.
        yaml.YAMLError: If config file is invalid YAML.
    """
    if config_path is None:
        config_path = Path(__file__).parent.parent / "config.yaml"
    else:
        config_path = Path(config_path)

    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    logger = logging.getLogger(__name__)
    logger.debug(f"Loading config from: {config_path}")

    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    return config