"""
Core package for BashGuard.
"""

from bashguard.core.logger import Logger
from bashguard.core.types import (
    ValueParameterExpansion, 
    ValuePlainVariable, 
    ValueUserInput, 
    ValueCommandSubtitution, 
    Value, 
    AssignedVariable, 
    UsedVariable, 
    Command, 
    Subscript, 
    InjectableVariable, 
    DeclaredPair,
    SensitiveValueUnionType
)
from bashguard.core.vulnerability import (
    Vulnerability, 
    Description, 
    SeverityLevel, 
    VulnerabilityType, 
    Recommendation
)
from bashguard.core.base_fixer import BaseFixer
from bashguard.core.reporter import Reporter
from bashguard.core.tsparser import TSParser
from bashguard.core.base_analyzer import BaseAnalyzer

__all__ = [
    "TSParser",
    "BaseAnalyzer",
    "Vulnerability",
    "Description",
    "SeverityLevel",
    "VulnerabilityType",
    "BaseFixer",
    "Logger",
    "Reporter",
    "ValueParameterExpansion",
    "ValuePlainVariable",
    "ValueUserInput",
    "ValueCommandSubtitution",
    "Value",
    "AssignedVariable",
    "UsedVariable",
    "Command",
    "Subscript",
    "InjectableVariable",
    "DeclaredPair",
    "Recommendation",
    "SensitiveValueUnionType"
]