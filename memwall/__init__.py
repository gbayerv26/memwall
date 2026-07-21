"""memwall: scanner for AI agent memory stores.

Detects memory poisoning (injected standing orders, exfiltration vectors,
hidden payloads) and hygiene issues (retained PII) in agent memory.
"""

__version__ = "0.5.0"

from .adapters import load  # noqa: F401
from .heuristics import scan_records  # noqa: F401
