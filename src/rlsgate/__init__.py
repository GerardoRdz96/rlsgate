"""rlsgate — the pre-deploy gate for vibe-coded apps.

Static, local-first scanner for the finite set of high-signal Supabase/RLS security
holes that leak vibe-coded apps' data. Detection is deterministic; the optional
AI-drafted fix is advisory and never auto-applied.
"""
from .findings import Finding, Severity
from .scanner import ScanResult, scan

__version__ = "0.1.0"
__all__ = ["scan", "ScanResult", "Finding", "Severity", "__version__"]
