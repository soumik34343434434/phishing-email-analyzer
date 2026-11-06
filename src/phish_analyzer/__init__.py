"""Offline phishing email triage."""

__version__ = "0.1.0"

from .analyzer import analyze  # noqa: E402
from .parser import parse_bytes, parse_file  # noqa: E402

__all__ = ["analyze", "parse_bytes", "parse_file", "__version__"]
