"""
Core package for BashGuard.
"""

from bashguard.core.vulnerability import Vulnerability, Description, SeverityLevel, VulnerabilityType
from bashguard.core.tsparser import TSParser
from bashguard.core.base_analyzer import BaseAnalyzer

__all__ = [
    "TSParser",
    "BaseAnalyzer",
    "Vulnerability",
    "Description",
    "SeverityLevel",
    "VulnerabilityType"
]