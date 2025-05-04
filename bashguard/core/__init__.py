"""
Core package for BashGuard.
"""

from bashguard.core.base_analyzer import BaseAnalyzer
from bashguard.core.parser import Parser
from bashguard.core.vulnerability import Vulnerability, Description, SeverityLevel, VulnerabilityType

__all__ = [
    "BaseAnalyzer",
    "Parser",
    "Vulnerability",
    "Description",
    "SeverityLevel",
    "VulnerabilityType"
]